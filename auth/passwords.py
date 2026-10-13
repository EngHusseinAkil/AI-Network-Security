from werkzeug.security import check_password_hash, generate_password_hash

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256


def validate_password(password):
    if (
        not isinstance(password, str)
        or not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in password)
    ):
        raise ValueError("Password must be 12 to 256 characters without control characters.")


def hash_password(password):
    validate_password(password)
    return generate_password_hash(password, method="scrypt")


def verify_password(stored_hash, password):
    try:
        return bool(stored_hash) and check_password_hash(stored_hash, password)
    except (ValueError, TypeError):
        return False
