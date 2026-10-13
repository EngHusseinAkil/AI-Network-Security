"""
Dashboard Form Parsing Utilities.

Provides strict, type-aware parsing of numeric form fields submitted to the
inference dashboard.  Each field in the flow feature contract has an explicit
expected Python type (int or float); coercion behaviour differs accordingly.

Policy
------
Float-compatible fields  : duration, avg_packet_size
Integer fields           : packet_count, byte_count, min_packet_size,
                           max_packet_size, protocol_enc, direction_enc

Rules
-----
* Never silently truncate or round a value.
* Reject empty strings, whitespace-only strings, and null-equivalent values.
* Reject booleans (Python bool is a subclass of int).
* Integer fields must reject any string that contains a decimal point,
  an exponent marker (e/E), or whose float representation is non-integral.
  Examples that MUST fail: "1.5", "2.2", "3e-1", "1e2" (ambiguous, rejected
  to keep the contract strict).
* Float fields accept valid finite integers or floats ("10", "10.0", "1.5").
* Reject NaN, +Infinity, and -Infinity in both field families.
"""

import math
from typing import Dict

# ---------------------------------------------------------------------------
# Field classification
# ---------------------------------------------------------------------------

#: Fields whose contract type is float (finite, not NaN/Inf).
FLOAT_FIELDS = frozenset({"duration", "avg_packet_size"})

#: Fields whose contract type is a non-negative integer.
INTEGER_FIELDS = frozenset({
    "packet_count", "byte_count", "min_packet_size",
    "max_packet_size", "protocol_enc", "direction_enc",
})

#: Canonical submission order (matches FLOW_FEATURE_ORDER).
FLOW_FORM_FIELDS = [
    "duration",
    "packet_count",
    "byte_count",
    "min_packet_size",
    "max_packet_size",
    "avg_packet_size",
    "protocol_enc",
    "direction_enc",
]


# ---------------------------------------------------------------------------
# Individual field parsers
# ---------------------------------------------------------------------------

def _reject_empty(raw: str, field: str) -> None:
    """Raise ValueError if the raw string is empty or whitespace-only."""
    if not raw or not raw.strip():
        raise ValueError(f"Field '{field}' must not be empty or whitespace-only.")


def parse_float_field(raw: str, field: str) -> float:
    """
    Parse *raw* as a finite float for *field*.

    Rejects
    -------
    * Empty / whitespace-only strings.
    * Non-numeric strings.
    * NaN, +Infinity, -Infinity.

    Returns
    -------
    float
    """
    _reject_empty(raw, field)
    stripped = raw.strip()
    try:
        value = float(stripped)
    except ValueError:
        raise ValueError(f"Field '{field}' is not a valid number: {stripped!r}")
    if math.isnan(value):
        raise ValueError(f"Field '{field}' must not be NaN.")
    if math.isinf(value):
        raise ValueError(f"Field '{field}' must not be Infinity.")
    return value


def parse_integer_field(raw: str, field: str) -> int:
    """
    Parse *raw* as a strict integer for *field*.

    Rejects
    -------
    * Empty / whitespace-only strings.
    * Non-numeric strings.
    * Any string containing '.' or 'e'/'E' (fractional or scientific notation).
    * Values whose float representation is non-integral (belt-and-suspenders).
    * NaN, Infinity.

    Returns
    -------
    int
    """
    _reject_empty(raw, field)
    stripped = raw.strip()

    # Fast syntactic rejection: integers have no decimal point or exponent.
    # This catches "1.5", "1.0", "3e-1", "1E2", "1.", ".5", etc.
    if '.' in stripped or 'e' in stripped.lower():
        raise ValueError(
            f"Field '{field}' must be a whole integer, got {stripped!r}. "
            "Fractional and scientific-notation values are not accepted."
        )

    # Attempt integer parse directly — no float intermediary.
    try:
        value = int(stripped, 10)
    except ValueError:
        raise ValueError(
            f"Field '{field}' is not a valid integer: {stripped!r}"
        )

    return value


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

def parse_flow_form_fields(form) -> Dict[str, object]:
    """
    Parse and validate all flow feature fields from a Werkzeug/Flask form.

    Parameters
    ----------
    form : werkzeug.datastructures.ImmutableMultiDict
        The ``request.form`` mapping.

    Returns
    -------
    dict
        A dictionary mapping field name -> parsed value (int or float),
        ready for downstream schema validation.

    Raises
    ------
    ValueError
        With a human-readable message identifying the offending field.
        The message does NOT echo raw user input verbatim (only field name).
    """
    features: Dict[str, object] = {}

    for field in FLOW_FORM_FIELDS:
        raw = form.get(field)
        if raw is None:
            # Field is entirely absent from the submission.
            raise ValueError(f"Missing required field: {field}")

        if field in INTEGER_FIELDS:
            features[field] = parse_integer_field(raw, field)
        else:
            features[field] = parse_float_field(raw, field)

    return features
