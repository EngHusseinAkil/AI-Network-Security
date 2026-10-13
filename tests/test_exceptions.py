from utils.exceptions import ApplicationError, ConfigurationError

def test_application_error_inheritance():
    assert issubclass(ConfigurationError, ApplicationError)
    assert issubclass(ApplicationError, Exception)

def test_application_error_to_dict():
    err = ConfigurationError("Test error", details={"info": "test"})
    d = err.to_dict()
    assert d["error_code"] == "CONFIG_ERROR"
    assert d["message"] == "Test error"
    assert d["details"] == {"info": "test"}

def test_application_error_str():
    err = ConfigurationError("Test error")
    assert str(err) == "[CONFIG_ERROR] Test error"
