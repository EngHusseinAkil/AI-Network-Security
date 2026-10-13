"""
Dashboard CSRF Protection.

Design
------
* Tokens are generated with ``secrets.token_hex(32)`` (256 bits of entropy).
* Each token is stored in the server-side Flask session under a private key.
* Submitted tokens are compared against the session token exclusively with
  ``secrets.compare_digest`` to prevent timing-oracle attacks.
* Tokens are NEVER echoed in log messages, error bodies, or URLs.
* Only POST requests are protected; safe GET requests are not checked.
* Feature values and predictions are NEVER stored in the session.

Session cookie security defaults are applied by
``configure_session_security`` which is called from the app factory.
Production startup logs a critical warning if the placeholder secret key
is detected.
"""

import logging
import secrets
from functools import wraps
from flask import session, request, abort

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CSRF_SESSION_KEY = "_csrf_token"

#: The placeholder value that ships in BaseSettings.  If Flask's SECRET_KEY
#: matches this at runtime, we emit a startup warning.
_DEV_PLACEHOLDER_KEY = "super-secret-placeholder-key-for-development"


# ---------------------------------------------------------------------------
# Token lifecycle
# ---------------------------------------------------------------------------

def generate_csrf_token() -> str:
    """
    Return the CSRF token bound to the current session.

    If the session does not yet have a token one is generated now and stored.
    The token is NOT logged at any level.
    """
    if CSRF_SESSION_KEY not in session:
        session[CSRF_SESSION_KEY] = secrets.token_hex(32)
    return session[CSRF_SESSION_KEY]


def validate_csrf_token(submitted_token: str) -> bool:
    """
    Validate *submitted_token* against the token stored in the current session.

    Returns False (rather than raising) when:
    * The session contains no token (missing session token).
    * The submitted token is absent or empty.
    * The tokens do not match.

    Always uses ``secrets.compare_digest`` to prevent timing attacks.
    The submitted token and the session token are NEVER logged.
    """
    session_token = session.get(CSRF_SESSION_KEY)
    if not session_token or not submitted_token:
        return False
    # Both operands must be str for compare_digest on Python 3.
    return secrets.compare_digest(session_token, submitted_token)


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------

def csrf_protect(f):
    """
    Decorator that enforces CSRF validation on POST requests.

    GET and other safe methods pass through without checking.
    On failure: aborts with HTTP 400.  The response body contains a generic
    message only — no token value is included.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            submitted = request.form.get("csrf_token")
            if not validate_csrf_token(submitted):
                # Log the path only, never the token.
                logger.warning(
                    "CSRF check failed for route %s. "
                    "Possible causes: missing session, expired session, "
                    "or cross-site request.",
                    request.path,
                )
                abort(400, "Invalid or missing CSRF token.")
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------------
# Application startup helpers
# ---------------------------------------------------------------------------

def configure_session_security(app) -> None:
    """
    Apply secure session-cookie defaults and warn on insecure secret keys.

    Call this once from the application factory before serving requests.
    """
    # Enforce HttpOnly so JavaScript cannot read the session cookie.
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)

    # SameSite=Lax prevents the cookie from being sent on cross-site POSTs
    # initiated by third-party sites (e.g., image tags, form submissions).
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")

    # Secure flag: restrict to HTTPS.  In testing/development this is left
    # False by default so the test client works without TLS.
    if not app.config.get("TESTING") and not app.config.get("DEBUG"):
        app.config.setdefault("SESSION_COOKIE_SECURE", True)
    else:
        app.config.setdefault("SESSION_COOKIE_SECURE", False)

    # Warn loudly if the placeholder development key is still in use.
    secret = app.config.get("SECRET_KEY", "")
    if secret == _DEV_PLACEHOLDER_KEY:
        if app.config.get("TESTING"):
            # Suppress noise in automated tests; tests inject their own key.
            pass
        elif app.config.get("DEBUG"):
            logger.warning(
                "APPLICATION SECURITY WARNING: SECRET_KEY is set to the "
                "development placeholder.  Set a strong unique SECRET_KEY "
                "via the SECRET_KEY environment variable before deploying."
            )
        else:
            # Production mode with placeholder key — this is a misconfiguration.
            logger.critical(
                "SECURITY CRITICAL: SECRET_KEY is the development placeholder "
                "in a non-debug environment.  Session integrity is COMPROMISED. "
                "Set SECRET_KEY via environment variable immediately."
            )
