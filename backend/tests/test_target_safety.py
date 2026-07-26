from __future__ import annotations

import pytest

from app.services.target_safety import LiveTargetSafetyError, validate_live_url_target


@pytest.mark.parametrize(
    "target",
    [
        "http://100.64.0.1",
        "http://192.0.2.1",
        "http://[fc00::1]",
    ],
)
def test_live_target_rejects_every_non_global_literal(target: str) -> None:
    with pytest.raises(LiveTargetSafetyError, match="must not"):
        validate_live_url_target(target)


def test_live_target_rejects_embedded_credentials() -> None:
    with pytest.raises(LiveTargetSafetyError, match="credentials"):
        validate_live_url_target("https://user:pass@8.8.8.8")


def test_live_target_accepts_global_literal() -> None:
    validate_live_url_target("https://8.8.8.8")
