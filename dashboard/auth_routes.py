from urllib.parse import urlsplit

from flask import (
    Blueprint, current_app, flash, redirect, render_template,
    request, session, url_for, g,
)

from dashboard.security import csrf_protect, generate_csrf_token

auth_bp = Blueprint("auth", __name__)


def _safe_next(value):
    if not value:
        return None
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or not value.startswith("/") or value.startswith("//"):
        return None
    return value


@auth_bp.route("/login", methods=["GET"])
def login_page():
    if getattr(g, "current_user", None):
        return redirect(url_for("dashboard.index"), code=303)
    return render_template(
        "dashboard/auth/login.html",
        next=_safe_next(request.args.get("next")),
        csrf_token=generate_csrf_token(),
        demo_mode=bool(current_app.config.get("DEMO_MODE")),
    )


@auth_bp.route("/login", methods=["POST"])
@csrf_protect
def login_submit():
    deps = current_app.extensions["dependencies"]
    user = deps.user_account_service.authenticate(
        request.form.get("login", ""), request.form.get("password", "")
    )
    destination = _safe_next(request.form.get("next")) or url_for("dashboard.index")
    request_id = getattr(g, "request_id", None)
    if not user:
        deps.security_audit_service.record(
            "login", "authentication", outcome="failed",
            request_id=request_id, safe_error_category="invalid_credentials",
        )
        flash("Invalid login credentials.", "error")
        return render_template(
            "dashboard/auth/login.html", next=destination,
            csrf_token=generate_csrf_token(),
            demo_mode=bool(current_app.config.get("DEMO_MODE")),
        ), 401
    session.clear()
    session["authenticated_user_id"] = user.public_user_id
    session.permanent = True
    generate_csrf_token()
    deps.security_audit_service.record(
        "login", "authentication", outcome="success",
        actor_public_user_id=user.public_user_id, request_id=request_id,
    )
    return redirect(destination, code=303)


@auth_bp.route("/logout", methods=["POST"])
@csrf_protect
def logout():
    deps = current_app.extensions["dependencies"]
    user = getattr(g, "current_user", None)
    deps.security_audit_service.record(
        "logout", "authentication", outcome="success",
        actor_public_user_id=user.public_user_id if user else None,
        request_id=getattr(g, "request_id", None),
    )
    session.clear()
    return redirect(url_for("auth.login_page"), code=303)
