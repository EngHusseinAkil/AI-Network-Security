import logging
from utils.logger import get_logger

def test_logger_initialization():
    logger = get_logger("TestLoggerInit")
    assert isinstance(logger, logging.Logger)
    assert len(logger.handlers) == 2  # Console and File
    
def test_no_duplicate_handlers():
    logger1 = get_logger("TestDuplicate")
    count = len(logger1.handlers)
    logger2 = get_logger("TestDuplicate")
    assert len(logger2.handlers) == count

def test_exception_logging(capsys):
    logger = get_logger("TestException")
    try:
        1 / 0
    except ZeroDivisionError:
        logger.exception("Intentional error")
    
    captured = capsys.readouterr()
    assert "Intentional error" in captured.out
    assert "ZeroDivisionError" in captured.out
