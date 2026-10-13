"""
Flask Application Factory.
"""
import logging
import time
from pathlib import Path
from flask import Flask, request, g

from config.settings import BaseSettings

def register_error_handlers(app: Flask):
    """Registers centralized error handlers."""
    from backend.errors.handlers import register_handlers
    register_handlers(app)

def register_blueprints(app: Flask):
    """Registers all application blueprints."""
    # Temporarily keeping internal_bp for tests, plus adding system_bp and ai_bp
    try:
        from backend.routes import internal_bp
        app.register_blueprint(internal_bp, url_prefix='/api/v1')
    except ImportError:
        pass

    from backend.routes.system import system_bp
    app.register_blueprint(system_bp, url_prefix='/api/v1')

    from backend.routes.ai import ai_bp
    app.register_blueprint(ai_bp, url_prefix='/api/v1')

    from backend.routes.inference import inference_bp
    app.register_blueprint(inference_bp, url_prefix='/api/v1/inference')

    from backend.routes.database import db_bp
    app.register_blueprint(db_bp, url_prefix='/api/v1')

    from backend.routes.monitoring import monitoring_bp
    app.register_blueprint(monitoring_bp, url_prefix='/api/v1/monitoring')

    # Register Dashboard Blueprint
    from dashboard.routes import dashboard_bp
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')

    from backend.routes.alerts import alerts_bp
    app.register_blueprint(alerts_bp, url_prefix='/api/v1/alerts')


def create_app(config_override=None, dependencies=None):
    """
    Creates and configures the Flask application.
    """
    app = Flask(__name__)

    # Configuration
    from config import settings as runtime_settings
    app.config.from_object(runtime_settings)
    app.config['TESTING'] = False
    app.config['DEBUG'] = False

    if config_override:
        app.config.update(config_override)
    if (
        app.config.get("TESTING")
        and (not config_override or "AUTHENTICATION_REQUIRED" not in config_override)
    ):
        app.config["AUTHENTICATION_REQUIRED"] = False

    from backend.services.production_config_service import ProductionConfigService
    from backend.services.request_id_service import RequestIdService
    startup_validation = ProductionConfigService().validate(app.config)
    if (
        app.config.get("ENVIRONMENT") == "production"
        and not startup_validation.ready
    ):
        raise RuntimeError(
            "Production configuration validation failed: "
            + ", ".join(startup_validation.errors)
        )

    trusted_proxy_hops = app.config.get("TRUSTED_PROXY_HOPS", 0)
    if trusted_proxy_hops:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=trusted_proxy_hops, x_proto=trusted_proxy_hops,
            x_host=trusted_proxy_hops, x_port=trusted_proxy_hops,
        )

    # Dependency Container setup
    from backend.dependencies import DependencyContainer
    if dependencies is None:
        dependencies = DependencyContainer(app.config)
    if (
        app.config.get("ENVIRONMENT") == "production"
        and app.config.get("MIGRATION_STRICT")
        and dependencies.migration_health_service.inspect().migration_required
    ):
        raise RuntimeError("Production database migration is required.")

    # Store dependencies safely on the app object for use in requests
    if not hasattr(app, 'extensions'):
        app.extensions = {}
    app.extensions['dependencies'] = dependencies

    # Initialize logging without duplicating handlers
    from utils.logger import get_logger
    logger = get_logger("FlaskApp")

    if not app.logger.handlers:
        for handler in logger.handlers:
            app.logger.addHandler(handler)
    app.logger.setLevel(logger.level)

    # Request ID Foundation
    @app.before_request
    def set_request_id():
        g.request_started_at = time.monotonic()
        g.request_id = RequestIdService().resolve(
            request.headers.get("X-Request-ID")
        )

    @app.after_request
    def add_request_id_header(response):
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        return response

    @app.after_request
    def log_request_outcome(response):
        from utils.structured_logging import log_event
        duration = max(
            0.0, (time.monotonic() - getattr(g, "request_started_at", time.monotonic()))
            * 1000
        )
        user = getattr(g, "current_user", None)
        log_event(
            app.logger, "info", "http_request",
            request_id=getattr(g, "request_id", None),
            actor_public_id=user.public_user_id if user else None,
            outcome=str(response.status_code), duration_ms=round(duration, 3),
        )
        return response

    from backend.security import setup_security_middleware
    setup_security_middleware(app)

    # Propagate the configured SECRET_KEY to app.secret_key so Flask's
    # session signing uses the same value as the rest of the application.
    # This must happen *before* blueprints are registered (some import
    # dashboard.security which reads the secret key at request time, but
    # having it set early avoids subtle ordering bugs).
    app.secret_key = app.config.get("SECRET_KEY")

    # Apply session-cookie security defaults and emit key-health warnings.
    from dashboard.security import configure_session_security
    configure_session_security(app)

    register_error_handlers(app)
    from backend.routes.operations import operations_bp
    app.register_blueprint(operations_bp)
    from dashboard.auth_routes import auth_bp
    app.register_blueprint(auth_bp)
    register_blueprints(app)
    from dashboard.authentication import install_authentication
    install_authentication(app)

    import click

    @app.cli.group("system")
    def system_cli():
        """Inspect production runtime readiness without mutation."""

    @system_cli.command("readiness")
    def readiness_command():
        report = dependencies.readiness_service.check(app.config)
        click.echo(f"status: {report['status']}")
        for name, state in sorted(report["components"].items()):
            click.echo(f"{name}: {state}")
        if report["status"] != "ready":
            raise click.exceptions.Exit(1)

    @system_cli.command("migration-status")
    def migration_status_command():
        status = dependencies.migration_health_service.inspect()
        click.echo(f"status: {status.status}")
        click.echo(f"current_revision: {status.current_revision or 'unknown'}")
        click.echo(f"expected_revision: {status.expected_revision}")
        if status.migration_required:
            raise click.exceptions.Exit(1)

    @system_cli.command("migration-upgrade")
    @click.confirmation_option(
        prompt="Confirm a verified backup exists and upgrade the schema?"
    )
    def migration_upgrade_command():
        from database.connection import get_engine
        from database.migrations import (
            milestone_20_defensive_actions, milestone_21_authentication,
        )
        engine = get_engine()
        milestone_20_defensive_actions.upgrade(engine)
        milestone_21_authentication.upgrade(engine)
        click.echo("Schema upgrade completed.")

    @system_cli.command("schema-create")
    @click.confirmation_option(prompt="Create the current schema in this database?")
    def schema_create_command():
        from database.schema import create_schema
        create_schema()
        click.echo("Current schema created.")

    @system_cli.command("migration-downgrade")
    @click.confirmation_option(
        prompt="Downgrade authentication and defensive-action schema?"
    )
    def migration_downgrade_command():
        from database.connection import get_engine
        from database.migrations import (
            milestone_20_defensive_actions, milestone_21_authentication,
        )
        engine = get_engine()
        milestone_21_authentication.downgrade(engine)
        milestone_20_defensive_actions.downgrade(engine)
        click.echo("Schema downgrade completed.")

    @app.cli.group("demo")
    def demo_cli():
        """Manage deterministic development-only demonstration data."""

    @demo_cli.command("seed")
    @click.confirmation_option(prompt="Seed deterministic demonstration data?")
    def seed_demo_command():
        environment = app.config.get("ENVIRONMENT")
        if environment not in {"development", "testing"}:
            raise click.ClickException("Demo seeding is unavailable in this environment.")
        if not app.config.get("DEMO_MODE"):
            raise click.ClickException("Set DEMO_MODE=true before seeding demo data.")
        from database.connection import get_engine
        from database.session import session_scope
        from database.seed import seed_demo_data
        from utils.exceptions import DatabaseError

        click.echo("WARNING: development-only demonstration data seeding.")
        click.echo(f"environment: {environment}")
        click.echo(f"database: {get_engine().url.render_as_string(hide_password=True)}")
        try:
            with session_scope() as session:
                result = seed_demo_data(session, confirm=True)
        except DatabaseError as exc:
            raise click.ClickException(f"Demo seeding failed: {exc}") from exc
        except Exception as exc:
            app.logger.error("Demo seeding failed and was rolled back: %s", exc)
            raise click.ClickException("Demo seeding failed; no records were committed.") from exc

        for entity, counts in result.entities.items():
            click.echo(
                f"{entity}: created={counts.created}, updated={counts.updated}, "
                f"reused={counts.reused}"
            )
            click.echo(f"  identifiers: {', '.join(counts.identifiers)}")
        click.echo("Deterministic demonstration data seeded; no user accounts were created.")

    @demo_cli.command("model")
    @click.option(
        "--dataset",
        "dataset_path",
        type=click.Path(path_type=Path),
        default=None,
        help="Trusted local flow CSV; defaults to data/samples/tiny_flow_sample.csv.",
    )
    @click.option("--model-version", default="demo-1.0.0", show_default=True)
    def bootstrap_demo_model_command(dataset_path, model_version):
        """Create and activate a deterministic development-only model."""
        if app.config.get("ENVIRONMENT") not in {"development", "testing"}:
            raise click.ClickException(
                "Demo model bootstrap is unavailable in production."
            )
        from ai.demo_model_bootstrap import bootstrap_demo_model
        from utils.exceptions import ValidationError

        dataset_path = dataset_path or (
            Path(app.config["DATA_DIR"]) / "samples" / "tiny_flow_sample.csv"
        )
        try:
            result = bootstrap_demo_model(
                dataset_path=dataset_path,
                models_dir=Path(app.config["MODELS_DIR"]),
                model_version=model_version,
            )
        except ValidationError as exc:
            raise click.ClickException(str(exc)) from exc

        click.echo(f"model_version: {result.model_version}")
        click.echo(f"dataset_path: {result.dataset_path}")
        click.echo(f"sample_count: {result.sample_count}")
        click.echo(f"discovered_labels: {', '.join(result.labels)}")
        click.echo(f"algorithm: {result.algorithm}")
        click.echo(f"artifact_directory: {result.artifact_directory}")
        click.echo(f"files_created: {', '.join(result.files_created)}")
        click.echo(f"registration_result: {result.registration_result}")
        click.echo(f"active_model_version: {result.active_model_version}")
        click.echo(
            "smoke_inference: "
            f"label={result.smoke_inference['predicted_canonical_label']}, "
            f"confidence={result.smoke_inference['confidence_score']:.6f}, "
            f"risk={result.smoke_inference['risk_score']:.6f}, "
            f"model={result.smoke_inference['model_version']}"
        )
        click.echo(f"evaluation_limitation: {result.evaluation_limitation}")
        click.echo(
            "WARNING: development and dashboard demonstration only; this tiny "
            "sample model is not production-ready."
        )

    @app.cli.group("users")
    def users_cli():
        """Provision local application users."""

    @users_cli.command("create")
    @click.option("--login", prompt=True)
    @click.option("--email", prompt=True)
    @click.option("--role", type=click.Choice(["admin", "operator", "viewer"]), prompt=True)
    @click.password_option(confirmation_prompt=True)
    def create_user(login, email, role, password):
        user = dependencies.user_account_service.provision(
            login, email, password, role
        )
        dependencies.security_audit_service.record(
            "user_provision", "user", user.public_user_id,
            actor_public_user_id=None,
        )
        click.echo(f"Created user {user.login_label} with role {user.role}.")

    @users_cli.command("list")
    def list_users():
        for user in dependencies.user_account_service.list_users():
            click.echo(f"{user.public_user_id}\t{user.login_label}\t{user.role}")

    def audit_user_change(action, user):
        dependencies.security_audit_service.record(
            action, "user", user.public_user_id, actor_public_user_id=None,
        )

    @users_cli.command("deactivate")
    @click.argument("public_user_id")
    @click.confirmation_option(prompt="Deactivate this user?")
    def deactivate_user(public_user_id):
        user = dependencies.user_account_service.set_active(public_user_id, False)
        audit_user_change("user_deactivate", user)
        click.echo(f"Deactivated user {user.login_label}.")

    @users_cli.command("activate")
    @click.argument("public_user_id")
    def activate_user(public_user_id):
        user = dependencies.user_account_service.set_active(public_user_id, True)
        audit_user_change("user_activate", user)
        click.echo(f"Activated user {user.login_label}.")

    @users_cli.command("role")
    @click.argument("public_user_id")
    @click.argument("role", type=click.Choice(["admin", "operator", "viewer"]))
    @click.confirmation_option(prompt="Change this user's role?")
    def change_user_role(public_user_id, role):
        user = dependencies.user_account_service.change_role(public_user_id, role)
        audit_user_change("user_role_change", user)
        click.echo(f"Changed user {user.login_label} to {user.role}.")

    @users_cli.command("reset-password")
    @click.argument("public_user_id")
    @click.password_option(confirmation_prompt=True)
    def reset_user_password(public_user_id, password):
        dependencies.user_account_service.reset_password(public_user_id, password)
        dependencies.security_audit_service.record(
            "user_password_reset", "user", public_user_id,
            actor_public_user_id=None,
        )
        click.echo("Password reset.")

    return app
