import pytest

from auth.passwords import hash_password, validate_password, verify_password


def test_password_hash_is_adaptive_and_verifies():
    password = "a sufficiently long password"
    stored = hash_password(password)
    assert stored != password
    assert stored.startswith("scrypt:")
    assert verify_password(stored, password)
    assert not verify_password(stored, "incorrect password")


@pytest.mark.parametrize("password", ["short", "a" * 257, "valid length\n"])
def test_password_policy_rejects_unsafe_values(password):
    with pytest.raises(ValueError):
        validate_password(password)


def test_malformed_password_hash_fails_safely():
    assert verify_password("not-a-supported-hash", "any password") is False
    assert verify_password(None, "any password") is False
