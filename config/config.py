import os
from config.environment import Environment
from config.settings import DevelopmentSettings, TestingSettings, ProductionSettings, BaseSettings

def load_config() -> BaseSettings:
    """
    Load the appropriate configuration settings based on the APP_ENV environment variable.
    Defaults to DevelopmentSettings.
    """
    env_str = os.getenv("APP_ENV", Environment.DEVELOPMENT.value).lower()
    
    try:
        # Validate that the environment is one of our explicitly supported values
        env = Environment(env_str)
    except ValueError:
        raise ValueError(f"Invalid APP_ENV: '{env_str}'. Supported values are: {[e.value for e in Environment]}")
    
    if env == Environment.PRODUCTION:
        return ProductionSettings()
    elif env == Environment.TESTING:
        return TestingSettings()
    
    return DevelopmentSettings()

# Global settings instance accessible throughout the application
settings = load_config()
