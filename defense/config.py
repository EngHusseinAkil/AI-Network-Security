from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DefensiveActionConfig:
    enabled: bool = False
    provider: str = "unavailable"
    fake_provider_permitted: bool = False
    default_duration_seconds: int = 900
    maximum_duration_seconds: int = 86_400
    maximum_retained_actions: int = 1_000
    token_max_age_seconds: int = 300
    minimum_severity: str = "high"
    schema_version: str = "defensive-action-v1"

    def __post_init__(self):
        if not isinstance(self.enabled, bool) or not isinstance(
            self.fake_provider_permitted, bool
        ):
            raise ValueError("defensive action flags must be boolean")
        if self.provider not in {"fake", "unavailable"}:
            raise ValueError("defensive action provider is not allowlisted")
        if self.provider == "fake" and not self.fake_provider_permitted:
            raise ValueError("fake defensive provider is restricted to testing or demo")
        for name, low, high in (
            ("default_duration_seconds", 60, 86_400),
            ("maximum_duration_seconds", 60, 86_400),
            ("maximum_retained_actions", 1, 10_000),
            ("token_max_age_seconds", 1, 300),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError(f"{name} is outside safe bounds")
        if self.default_duration_seconds > self.maximum_duration_seconds:
            raise ValueError("default duration exceeds maximum duration")
        if self.minimum_severity not in {"high", "critical"}:
            raise ValueError("minimum severity must be high or critical")
        if (
            not isinstance(self.schema_version, str)
            or not self.schema_version
            or len(self.schema_version) > 64
            or any(ord(ch) < 33 or ord(ch) > 126 for ch in self.schema_version)
        ):
            raise ValueError("schema_version must be a bounded printable token")
