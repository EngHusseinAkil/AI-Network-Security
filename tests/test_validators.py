from utils.validators import validate_string, validate_port, validate_dictionary_keys

def test_validate_string():
    assert validate_string("test") is True
    assert validate_string("") is False
    assert validate_string("  ") is False
    assert validate_string(123) is False

def test_validate_port():
    assert validate_port(80) is True
    assert validate_port(65535) is True
    assert validate_port(0) is False
    assert validate_port(99999) is False
    assert validate_port("invalid") is False

def test_validate_dictionary_keys():
    assert validate_dictionary_keys({"a": 1, "b": 2}, ["a"]) is True
    assert validate_dictionary_keys({"a": 1}, ["a", "b"]) is False
    assert validate_dictionary_keys([], ["a"]) is False
