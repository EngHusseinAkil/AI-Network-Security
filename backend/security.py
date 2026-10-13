"""
Security Middleware for the Application.
Handles Secure Headers, JSON Policy, CORS, and Rate Limiting.
"""
import time
import logging
from functools import wraps
from flask import request, current_app, make_response, g
from werkzeug.exceptions import UnsupportedMediaType

from backend.errors.exceptions import ApiError

logger = logging.getLogger(__name__)

class RateLimitExceededError(ApiError):
    def __init__(self, message="Rate limit exceeded.", retry_after=60):
        super().__init__(message, "RATE_LIMIT_EXCEEDED", 429, {"retry_after": retry_after})

# In-memory rate limiting store (for development/tests)
# Structure: { key: { 'count': int, 'reset_time': float } }
_rate_limits = {}

def get_client_ip():
    """Extracts client IP. In production, respect proxies only if configured."""
    # Development fallback
    return request.remote_addr or "127.0.0.1"

def rate_limit(limit_key_config="RATE_LIMIT_DEFAULT"):
    """
    Decorator for rate limiting endpoints.
    Reads limit from app.config using the limit_key_config.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_app.config.get('TESTING', False) and not current_app.config.get('TESTING_RATE_LIMITS', False):
                return f(*args, **kwargs)

            limit = current_app.config.get(limit_key_config, 60)
            client_ip = get_client_ip()
            # The rate limit key ensures separation of limits per endpoint logic and client
            # The URL rule or endpoint name combined with IP forms a robust key.
            # Normalizing safely:
            key = f"rl:{request.endpoint}:{client_ip}"

            now = time.time()
            window = 60 # 1 minute window

            if key not in _rate_limits:
                _rate_limits[key] = {"count": 1, "reset_time": now + window}
            else:
                record = _rate_limits[key]
                if now > record["reset_time"]:
                    record["count"] = 1
                    record["reset_time"] = now + window
                else:
                    record["count"] += 1
                    if record["count"] > limit:
                        retry_after = int(record["reset_time"] - now)
                        logger.warning("Rate limit exceeded for %s on endpoint %s", client_ip, request.endpoint)
                        raise RateLimitExceededError(retry_after=max(1, retry_after))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def setup_security_middleware(app):
    """Registers before_request and after_request hooks for security policies."""

    @app.before_request
    def enforce_json_policy():
        """Ensure endpoints requiring JSON get application/json."""
        if getattr(request, 'routing_exception', None) is not None:
            return

        if request.method in ["POST", "PUT", "PATCH"]:
            if request.path.startswith('/api/'):
                # We enforce application/json for API modification endpoints
                content_type = request.content_type
                if not content_type or not content_type.startswith("application/json"):
                    # We raise standard UnsupportedMediaType
                    raise UnsupportedMediaType("Content-Type must be application/json")

    @app.before_request
    def handle_preflight_cors():
        """Handles CORS preflight OPTIONS requests."""
        if request.method == "OPTIONS":
            origin = request.headers.get("Origin")
            allowed_origins = app.config.get("CORS_ALLOWED_ORIGINS", [])

            if not allowed_origins:
                # No origins allowed -> reject preflight
                return make_response("", 403)

            if origin in allowed_origins:
                response = make_response()
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Request-ID"
                response.headers["Access-Control-Max-Age"] = "86400"
                if app.config.get("CORS_ALLOW_CREDENTIALS"):
                    response.headers["Access-Control-Allow-Credentials"] = "true"
                return response, 200
            else:
                return make_response("", 403)

    @app.after_request
    def add_security_headers(response):
        """Adds CORS and secure headers to the response."""
        # Secure headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store, max-age=0'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self';"
        )
        response.headers['Permissions-Policy'] = "geolocation=(), microphone=(), camera=()"
        if (
            app.config.get("ENVIRONMENT") == "production"
            and request.is_secure
        ):
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        # CORS headers for actual requests
        origin = request.headers.get("Origin")
        allowed_origins = app.config.get("CORS_ALLOWED_ORIGINS", [])

        if origin and origin in allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            if app.config.get("CORS_ALLOW_CREDENTIALS"):
                response.headers["Access-Control-Allow-Credentials"] = "true"

        return response
