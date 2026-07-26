from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parent.parent / "scripts" / "production_saas_smoke.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("production_saas_smoke", SCRIPT_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_deep_health_requires_database_and_active_runner(monkeypatch):
    module = _load_module()

    def fake_request(url, **_kwargs):
        assert url == "https://threatgenix.example/api/health?deep=true"
        return (
            200,
            b'{"status":"ok","database":"connected","alembic_revision":"068","validation_runner":{"status":"ready","active_worker_count":1}}',
            "application/json",
        )

    monkeypatch.setattr(module, "_request", fake_request)

    result = module.check_deep_health("https://threatgenix.example")

    assert result.status == "pass"
    assert "active workers 1" in result.detail


def test_deep_health_fails_when_managed_runner_has_no_workers(monkeypatch):
    module = _load_module()

    monkeypatch.setattr(
        module,
        "_request",
        lambda *_args, **_kwargs: (
            200,
            b'{"status":"ok","database":"connected","alembic_revision":"068","validation_runner":{"status":"ready","active_worker_count":0}}',
            "application/json",
        ),
    )

    result = module.check_deep_health("https://threatgenix.example")

    assert result.status == "fail"
    assert "no active managed validation worker" in result.detail


def test_deep_health_requires_expected_alembic_revision(monkeypatch):
    module = _load_module()
    monkeypatch.setattr(
        module,
        "_request",
        lambda *_args, **_kwargs: (
            200,
            b'{"status":"ok","database":"connected","alembic_revision":"062","validation_runner":{"status":"ready","active_worker_count":1}}',
            "application/json",
        ),
    )

    result = module.check_deep_health("https://threatgenix.example")

    assert result.status == "fail"
    assert "expected 068" in result.detail


def test_runner_heartbeat_advances_requires_newer_second_heartbeat(monkeypatch):
    module = _load_module()
    health_bodies = [
        (
            200,
            {
                "status": "ok",
                "database": "connected",
                "alembic_revision": "068",
                "validation_runner": {
                    "status": "ready",
                    "active_worker_count": 1,
                    "last_heartbeat_at": "2026-04-29T10:00:00+00:00",
                },
            },
        ),
        (
            200,
            {
                "status": "ok",
                "database": "connected",
                "alembic_revision": "068",
                "validation_runner": {
                    "status": "ready",
                    "active_worker_count": 1,
                    "last_heartbeat_at": "2026-04-29T10:00:12+00:00",
                },
            },
        ),
    ]

    monkeypatch.setattr(
        module, "_get_deep_health_body", lambda _base_url: health_bodies.pop(0)
    )
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    result = module.check_runner_heartbeat_advances("https://threatgenix.example")

    assert result.status == "pass"
    assert "heartbeat advanced" in result.detail


def test_unauthenticated_auth_gate_requires_rejection(monkeypatch):
    module = _load_module()
    monkeypatch.setattr(
        module, "_request", lambda *_args, **_kwargs: (401, b"{}", "application/json")
    )

    result = module.check_unauthenticated_auth_gate("https://threatgenix.example")

    assert result.status == "pass"


def test_authenticated_validation_lab_api_skips_without_token():
    module = _load_module()

    result = module.check_authenticated_validation_lab_api(
        "https://threatgenix.example",
        "model-1",
        None,
    )

    assert result.status == "skip"


def test_run_smoke_api_only_skips_frontend_spa_route(monkeypatch):
    module = _load_module()

    monkeypatch.setattr(
        module,
        "check_deep_health",
        lambda *_args, **_kwargs: module.SmokeResult("deep_health", "pass", "ok"),
    )
    monkeypatch.setattr(
        module,
        "check_unauthenticated_auth_gate",
        lambda *_args, **_kwargs: module.SmokeResult(
            "unauthenticated_auth_gate", "pass", "ok"
        ),
    )
    monkeypatch.setattr(
        module,
        "check_validation_lab_route",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("SPA route should be skipped")
        ),
    )
    monkeypatch.setattr(
        module,
        "check_authenticated_validation_lab_api",
        lambda *_args, **_kwargs: module.SmokeResult(
            "authenticated_validation_lab_api", "skip", "no token"
        ),
    )

    results = module.run_smoke(
        "https://threatgenix.example",
        "model-1",
        None,
        api_only=True,
    )

    assert results[2].name == "validation_lab_route"
    assert results[2].status == "skip"


def test_synthetic_byok_save_delete_masks_and_deletes_dummy_key(monkeypatch):
    module = _load_module()
    list_calls = 0
    dummy_key = "sk-ant-api03-codex-smoke-not-real-feedface"

    monkeypatch.setattr(module.secrets, "token_hex", lambda _size: "feedface")

    def fake_request(url, **kwargs):
        nonlocal list_calls
        method = kwargs.get("method", "GET")
        if (
            url == "https://threatgenix.example/api/llm/keys/anthropic"
            and method == "PUT"
        ):
            assert kwargs["json_body"]["api_key"] == dummy_key
            return (
                200,
                b'{"provider":"anthropic","display_name":"Anthropic","masked_key":"sk-ant...face","model_override":"claude-opus-prod-smoke-not-called","created_at":"2026-04-29T00:00:00Z"}',
                "application/json",
            )
        if url == "https://threatgenix.example/api/llm/keys" and method == "GET":
            list_calls += 1
            if list_calls == 1:
                return (
                    200,
                    b'[{"provider":"anthropic","masked_key":"sk-ant...face"}]',
                    "application/json",
                )
            return 200, b"[]", "application/json"
        if (
            url == "https://threatgenix.example/api/llm/keys/anthropic"
            and method == "DELETE"
        ):
            return 204, b"", "application/json"
        raise AssertionError(f"unexpected request {method} {url}")

    monkeypatch.setattr(module, "_request", fake_request)

    result = module.check_synthetic_byok_save_delete(
        "https://threatgenix.example", "token"
    )

    assert result.status == "pass"
    assert dummy_key not in result.detail


def test_synthetic_assistant_copilot_fails_on_degraded_provider(monkeypatch):
    module = _load_module()

    monkeypatch.setattr(
        module,
        "_request",
        lambda *_args, **_kwargs: (
            200,
            b'{"mode":"ask","answer":"Fallback","degraded_reason":"Assistant fell back to deterministic mode: RuntimeError"}',
            "application/json",
        ),
    )

    result = module.check_synthetic_assistant_copilot(
        "https://threatgenix.example",
        "token",
        "model-1",
    )

    assert result.status == "fail"
    assert "degraded" in result.detail


def test_synthetic_authenticated_journey_runs_auth_lab_byok_and_assistant(monkeypatch):
    module = _load_module()
    created_model_id = "11111111-1111-1111-1111-111111111111"
    registered_email = ""

    def fake_post_json(_base_url, path, body, *, token=None):
        nonlocal registered_email
        if path == "/api/auth/register":
            assert body["email"].startswith("codex-prod-smoke-")
            assert body["email"].endswith("@example.com")
            registered_email = body["email"]
            return 201, {"email": body["email"]}
        if path == "/api/auth/login":
            assert token is None
            return 200, {"access_token": "synthetic-token"}
        if path == "/api/threat-models":
            assert token == "synthetic-token"
            assert body["data_classification"] == "Internal"
            return 201, {"id": created_model_id}
        raise AssertionError(f"unexpected POST {path}")

    def fake_request(url, **kwargs):
        assert url == "https://threatgenix.example/api/auth/me"
        assert kwargs["token"] == "synthetic-token"
        return (
            200,
            f'{{"email":"{registered_email}"}}'.encode("utf-8"),
            "application/json",
        )

    monkeypatch.setattr(module, "_post_json", fake_post_json)
    monkeypatch.setattr(module, "_request", fake_request)
    monkeypatch.setattr(
        module,
        "check_authenticated_validation_lab_api",
        lambda base_url, threat_model_id, token: module.SmokeResult(
            "authenticated_validation_lab_api",
            "pass",
            f"{base_url} {threat_model_id} {token}",
        ),
    )
    monkeypatch.setattr(
        module,
        "check_synthetic_byok_save_delete",
        lambda base_url, token: module.SmokeResult(
            "synthetic_byok_save_delete",
            "pass",
            f"{base_url} {token}",
        ),
    )
    monkeypatch.setattr(
        module,
        "check_synthetic_assistant_copilot",
        lambda base_url, token, threat_model_id: module.SmokeResult(
            "synthetic_assistant_copilot",
            "pass",
            f"{base_url} {token} {threat_model_id}",
        ),
    )

    result = module.check_synthetic_authenticated_journey(
        "https://threatgenix.example",
        assistant_live=True,
    )

    assert result.status == "pass"
    assert "BYOK save/delete passed" in result.detail
    assert "assistant/copilot passed" in result.detail


def test_synthetic_validation_tool_runs_completes_offline_tools_and_fail_closed_network_tools(
    monkeypatch,
):
    module = _load_module()
    scheduled: dict[str, str] = {}

    def fake_post_json(_base_url, path, body, *, token=None):
        assert token == "token"
        if path == "/api/threat-models/model-1/validation-lab/schedules":
            tool_name = body["tool_name"]
            if tool_name == "nuclei":
                return (
                    201,
                    {
                        "id": f"schedule-{tool_name}",
                        "runnable": False,
                        "blocked_reason": (
                            f"{tool_name} execution is disabled until sandbox "
                            "enforcement is enabled"
                        ),
                    },
                )
            expected_target = (
                "/tmp/threatgenix-validation-targets/repo#requirements.txt"
                if tool_name == "osv-scanner"
                else "/tmp/threatgenix-validation-targets/repo"
            )
            assert body["target"] == expected_target
            scheduled[f"schedule-{tool_name}"] = tool_name
            return 201, {"id": f"schedule-{tool_name}", "runnable": True}
        if path.endswith("/run"):
            schedule_id = path.split("/")[-2]
            tool_name = scheduled[schedule_id]
            return 201, {"id": f"scan-{tool_name}"}
        raise AssertionError(f"unexpected POST {path}")

    def fake_get_scan_detail(_base_url, *, token, threat_model_id, scan_id):
        assert token == "token"
        assert threat_model_id == "model-1"
        tool_name = scan_id.removeprefix("scan-")
        return 200, {
            "status": "completed",
            "finding_count": 1 if tool_name != "trufflehog" else 0,
        }

    monkeypatch.setattr(module, "_post_json", fake_post_json)
    monkeypatch.setattr(module, "_get_scan_detail", fake_get_scan_detail)

    result = module.check_synthetic_validation_tool_runs(
        "https://threatgenix.example",
        token="token",
        threat_model_id="model-1",
        validation_target="/tmp/threatgenix-validation-targets/repo",
    )

    assert result.status == "pass"
    assert "semgrep=1 findings" in result.detail
    assert "trufflehog=0 findings" in result.detail
    assert "fail-closed nuclei" in result.detail


def test_synthetic_authenticated_journey_can_upload_target_bundle_for_tool_smoke(
    monkeypatch,
):
    module = _load_module()
    created_model_id = "11111111-1111-1111-1111-111111111111"
    registered_email = ""

    def fake_post_json(_base_url, path, body, *, token=None):
        nonlocal registered_email
        if path == "/api/auth/register":
            registered_email = body["email"]
            return 201, {"email": body["email"]}
        if path == "/api/auth/login":
            return 200, {"access_token": "synthetic-token"}
        if path == "/api/threat-models":
            return 201, {"id": created_model_id}
        raise AssertionError(f"unexpected POST {path}")

    monkeypatch.setattr(module, "_post_json", fake_post_json)
    monkeypatch.setattr(
        module,
        "_request",
        lambda *_args, **_kwargs: (
            200,
            f'{{"email":"{registered_email}"}}'.encode(),
            "application/json",
        ),
    )
    monkeypatch.setattr(
        module,
        "check_authenticated_validation_lab_api",
        lambda *_args, **_kwargs: module.SmokeResult(
            "authenticated_validation_lab_api", "pass", "lab ok"
        ),
    )
    monkeypatch.setattr(
        module,
        "check_synthetic_byok_save_delete",
        lambda *_args, **_kwargs: module.SmokeResult(
            "synthetic_byok_save_delete", "pass", "byok ok"
        ),
    )
    monkeypatch.setattr(
        module,
        "upload_synthetic_validation_target_bundle",
        lambda *_args, **_kwargs: "tgx-target://11111111-1111-1111-1111-111111111111",
    )

    def fake_validation_tool_runs(_base_url, *, validation_target, **_kwargs):
        assert validation_target == "tgx-target://11111111-1111-1111-1111-111111111111"
        return module.SmokeResult("synthetic_validation_tool_runs", "pass", "tools ok")

    monkeypatch.setattr(
        module, "check_synthetic_validation_tool_runs", fake_validation_tool_runs
    )

    result = module.check_synthetic_authenticated_journey(
        "https://threatgenix.example",
        validation_upload=True,
    )

    assert result.status == "pass"
    assert "tools ok" in result.detail


def test_synthetic_validation_tool_runs_rejects_generic_disabled_tool_http_error(
    monkeypatch,
):
    module = _load_module()
    monkeypatch.setattr(module, "OFFLINE_VALIDATION_TOOL_CHECKS", ())
    monkeypatch.setattr(
        module,
        "DISABLED_MANAGED_TOOL_CHECKS",
        (("nuclei", "url", "https://example.com"),),
    )
    monkeypatch.setattr(
        module,
        "_post_json",
        lambda *_args, **_kwargs: (401, {"detail": "not authenticated"}),
    )

    result = module.check_synthetic_validation_tool_runs(
        "https://threatgenix.example",
        token="token",
        threat_model_id="model-1",
        validation_target="/tmp/threatgenix-validation-targets/repo",
    )

    assert result.status == "fail"
    assert "expected fail-closed" in result.detail


def test_synthetic_validation_tool_runs_rejects_unexpected_blocked_reason(monkeypatch):
    module = _load_module()
    monkeypatch.setattr(module, "OFFLINE_VALIDATION_TOOL_CHECKS", ())
    monkeypatch.setattr(
        module,
        "DISABLED_MANAGED_TOOL_CHECKS",
        (("nuclei", "url", "https://example.com"),),
    )
    monkeypatch.setattr(
        module,
        "_post_json",
        lambda *_args, **_kwargs: (
            201,
            {
                "id": "schedule-nuclei",
                "runnable": False,
                "blocked_reason": "target rejected",
            },
        ),
    )

    result = module.check_synthetic_validation_tool_runs(
        "https://threatgenix.example",
        token="token",
        threat_model_id="model-1",
        validation_target="/tmp/threatgenix-validation-targets/repo",
    )

    assert result.status == "fail"
    assert "unexpected blocked reason" in result.detail
