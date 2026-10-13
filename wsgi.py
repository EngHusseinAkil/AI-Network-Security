"""Production WSGI entry point. Importing creates the inert Flask app only."""
from backend.app_factory import create_app

app = create_app()
