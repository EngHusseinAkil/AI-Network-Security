import base64
import re


_URLSAFE_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")


def is_canonical_signed_token(token):
    if not isinstance(token, str) or not 1 <= len(token) <= 4096:
        return False
    segments = token.split(".")
    if len(segments) not in {3, 4}:
        return False
    if len(segments) == 4 and segments[0] != "":
        return False
    for segment in segments[1:] if segments[0] == "" else segments:
        if not segment or not _URLSAFE_SEGMENT.fullmatch(segment):
            return False
        try:
            decoded = base64.urlsafe_b64decode(
                segment + "=" * (-len(segment) % 4)
            )
        except Exception:
            return False
        canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
        if canonical != segment:
            return False
    return True
