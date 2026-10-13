import logging
from logging.handlers import TimedRotatingFileHandler
import os
import sys
from pathlib import Path

from config import settings

def get_logger(name: str) -> logging.Logger:
    """
    Returns a configured logger with console and daily rotating file handlers.
    Prevents duplicate handlers if called multiple times for the same logger name.
    """
    logger = logging.getLogger(name)
    
    # Use the application's global log level
    log_level_str = getattr(settings, "LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_str, logging.INFO)
    
    # Only configure if the logger doesn't already have handlers to prevent duplication
    if not logger.handlers:
        logger.setLevel(log_level)
        
        # Define a detailed formatting string
        # [Timestamp] [Level] [LoggerName] [Module:Function] Message
        log_format = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s] [%(module)s:%(funcName)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        
        # 1. Console Handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(log_format)
        logger.addHandler(console_handler)
        
        if getattr(settings, "LOG_DESTINATION", "file") == "file":
            logs_dir = Path(settings.LOGS_DIR)
            logs_dir.mkdir(parents=True, exist_ok=True)
            log_file = logs_dir / f"{settings.APP_NAME.lower()}.log"
            file_handler = TimedRotatingFileHandler(
                filename=log_file,
                when="midnight",
                interval=1,
                backupCount=30,
                encoding="utf-8"
            )
            file_handler.setFormatter(log_format)
            logger.addHandler(file_handler)
        
        # Ensure that this logger doesn't pass messages to the root logger to avoid double printing
        logger.propagate = False

    return logger
