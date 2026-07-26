#!/usr/bin/env python3
"""Production-safe SaaS smoke checks for the deployed ThreatGenix control plane.

The default checks make no authenticated requests, do not submit validation runs,
and do not upload customer data. Set THREATGENIX_PROD_E2E_TOKEN to add a read-only
authenticated Validation Lab API check for a known tenant/model.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from io import BytesIO
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen
import zipfile

DEFAULT_BASE_URL = "https://threatgenix.vercel.app"
DEFAULT_MODEL_ID = "00000000-0000-0000-0000-000000000010"
EXPECTED_ALEMBIC_REVISION = "068"
READINESS_RUNNER_STATES = {"ready", "queued", "running"}
OFFLINE_VALIDATION_TOOL_CHECKS = (
    ("semgrep", "repository_path"),
    ("trivy", "iac_directory"),
    ("checkov", "iac_directory"),
    ("trufflehog", "repository_path"),
)
DISABLED_MANAGED_TOOL_CHECKS = (
    ("nuclei", "url", "https://example.com"),
)


@dataclass(frozen=True)
class SmokeResult:
    name: str
    status: str
    detail: str


def _url(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _request(
    url: str,
    *,
    token: str | None = None,
    accept: str = "application/json",
    method: str = "GET",
    json_body: dict[str, Any] | None = None,
    timeout: float = 20.0,
) -> tuple[int, bytes, str]:
    headers = {"Accept": accept, "User-Agent": "threatgenix-prod-saas-smoke/1.0"}
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            return (
                response.status,
                response.read(),
                response.headers.get("content-type", ""),
            )
    except HTTPError as exc:
        return exc.code, exc.read(), exc.headers.get("content-type", "")
    except URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc


def _request_multipart(
    url: str,
    *,
    token: str,
    fields: dict[str, str],
    file_field: str,
    filename: str,
    file_content_type: str,
    file_bytes: bytes,
    timeout: float = 60.0,
) -> tuple[int, bytes, str]:
    boundary = f"----threatgenix-smoke-{secrets.token_hex(12)}"
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode("utf-8"),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(
                    "utf-8"
                ),
                str(value).encode("utf-8"),
                b"\r\n",
            ]
        )
    chunks.extend(
        [
            f"--{boundary}\r\n".encode("utf-8"),
            (
                f'Content-Disposition: form-data; name="{file_field}"; '
                f'filename="{filename}"\r\n'
            ).encode("utf-8"),
            f"Content-Type: {file_content_type}\r\n\r\n".encode("utf-8"),
            file_bytes,
            b"\r\n",
            f"--{boundary}--\r\n".encode("utf-8"),
        ]
    )
    body = b"".join(chunks)
    request = Request(
        url,
        data=body,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "threatgenix-prod-saas-smoke/1.0",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            return (
                response.status,
                response.read(),
                response.headers.get("content-type", ""),
            )
    except HTTPError as exc:
        return exc.code, exc.read(), exc.headers.get("content-type", "")
    except URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc


def _json_body(raw: bytes) -> dict[str, Any]:
    document = _json_document(raw)
    if not isinstance(document, dict):
        raise ValueError("response JSON was not an object")
    return document


def _json_document(raw: bytes) -> Any:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("response was not valid JSON") from exc
    return document


def _post_json(
    base_url: str,
    path: str,
    body: dict[str, Any],
    *,
    token: str | None = None,
) -> tuple[int, dict[str, Any]]:
    status, raw, _content_type = _request(
        _url(base_url, path),
        token=token,
        method="POST",
        json_body=body,
    )
    return status, _json_body(raw)


def _get_deep_health_body(base_url: str) -> tuple[int, dict[str, Any]]:
    status, raw, _content_type = _request(_url(base_url, "/api/health?deep=true"))
    return status, _json_body(raw)


def check_deep_health(
    base_url: str, *, expected_source_version: str | None = None
) -> SmokeResult:
    try:
        status, body = _get_deep_health_body(base_url)
    except Exception as exc:
        return SmokeResult("deep_health", "fail", str(exc))
    if status != 200:
        return SmokeResult("deep_health", "fail", f"HTTP {status}: {body}")
    if body.get("status") != "ok":
        return SmokeResult(
            "deep_health", "fail", f"health status is {body.get('status')!r}"
        )
    if body.get("database") != "connected":
        return SmokeResult("deep_health", "fail", "database was not connected")
    if (
        expected_source_version
        and body.get("source_version") != expected_source_version
    ):
        return SmokeResult(
            "deep_health",
            "fail",
            (
                "source version was "
                f"{body.get('source_version')!r}; expected {expected_source_version}"
            ),
        )
    if body.get("alembic_revision") != EXPECTED_ALEMBIC_REVISION:
        return SmokeResult(
            "deep_health",
            "fail",
            (
                "alembic revision was "
                f"{body.get('alembic_revision')!r}; expected {EXPECTED_ALEMBIC_REVISION}"
            ),
        )
    runner = body.get("validation_runner")
    if isinstance(runner, dict):
        runner_status = str(runner.get("status") or "")
        active_workers = int(runner.get("active_worker_count") or 0)
        if runner_status not in READINESS_RUNNER_STATES:
            return SmokeResult(
                "deep_health", "fail", f"runner status is {runner_status!r}"
            )
        if active_workers < 1:
            return SmokeResult(
                "deep_health", "fail", "no active managed validation worker"
            )
        return SmokeResult(
            "deep_health",
            "pass",
            f"database connected; runner {runner_status}; active workers {active_workers}",
        )
    return SmokeResult(
        "deep_health", "pass", "database connected; runner not configured"
    )


def _heartbeat_timestamp(body: dict[str, Any]) -> str | None:
    runner = body.get("validation_runner")
    if not isinstance(runner, dict):
        return None
    value = runner.get("last_heartbeat_at")
    return value if isinstance(value, str) and value else None


def check_runner_heartbeat_advances(
    base_url: str, *, timeout_seconds: float = 75.0, poll_seconds: float = 5.0
) -> SmokeResult:
    """Prove the deployed managed worker keeps emitting fresh heartbeats."""
    try:
        first_status, first_body = _get_deep_health_body(base_url)
        first_heartbeat = _heartbeat_timestamp(first_body)
        if first_status != 200 or first_heartbeat is None:
            return SmokeResult(
                "runner_heartbeat_advances",
                "fail",
                f"first deep health did not expose a runner heartbeat: HTTP {first_status}: {first_body}",
            )
        deadline = time.monotonic() + timeout_seconds
        second_status = first_status
        second_body = first_body
        second_heartbeat = first_heartbeat
        while time.monotonic() < deadline:
            time.sleep(poll_seconds)
            second_status, second_body = _get_deep_health_body(base_url)
            second_heartbeat = _heartbeat_timestamp(second_body)
            if (
                second_status == 200
                and second_heartbeat is not None
                and second_heartbeat > first_heartbeat
            ):
                return SmokeResult(
                    "runner_heartbeat_advances",
                    "pass",
                    f"heartbeat advanced from {first_heartbeat} to {second_heartbeat}",
                )
    except Exception as exc:
        return SmokeResult("runner_heartbeat_advances", "fail", str(exc))

    if second_status != 200 or second_heartbeat is None:
        return SmokeResult(
            "runner_heartbeat_advances",
            "fail",
            f"second deep health did not expose a runner heartbeat: HTTP {second_status}: {second_body}",
        )
    if second_heartbeat <= first_heartbeat:
        return SmokeResult(
            "runner_heartbeat_advances",
            "fail",
            f"heartbeat did not advance: first={first_heartbeat}, second={second_heartbeat}",
        )
    return SmokeResult(
        "runner_heartbeat_advances",
        "pass",
        f"heartbeat advanced from {first_heartbeat} to {second_heartbeat}",
    )


def check_unauthenticated_auth_gate(base_url: str) -> SmokeResult:
    try:
        status, _raw, _content_type = _request(_url(base_url, "/api/auth/me"))
    except Exception as exc:
        return SmokeResult("unauthenticated_auth_gate", "fail", str(exc))
    if status in {401, 403}:
        return SmokeResult(
            "unauthenticated_auth_gate", "pass", f"/api/auth/me returned HTTP {status}"
        )
    return SmokeResult(
        "unauthenticated_auth_gate",
        "fail",
        f"/api/auth/me should reject anonymous users, got HTTP {status}",
    )


def check_validation_lab_route(base_url: str, threat_model_id: str) -> SmokeResult:
    try:
        status, raw, content_type = _request(
            _url(base_url, f"/threat-models/{threat_model_id}/validation-lab"),
            accept="text/html",
        )
    except Exception as exc:
        return SmokeResult("validation_lab_route", "fail", str(exc))
    if status != 200:
        return SmokeResult("validation_lab_route", "fail", f"HTTP {status}")
    body = raw.decode("utf-8", errors="replace")
    if "text/html" not in content_type and "<html" not in body.lower():
        return SmokeResult("validation_lab_route", "fail", "route did not return HTML")
    if "ThreatGenix" not in body and 'id="root"' not in body:
        return SmokeResult("validation_lab_route", "fail", "SPA shell marker missing")
    return SmokeResult(
        "validation_lab_route",
        "pass",
        "Validation Lab SPA route returned the app shell",
    )


def check_authenticated_validation_lab_api(
    base_url: str,
    threat_model_id: str,
    token: str | None,
) -> SmokeResult:
    if not token:
        return SmokeResult(
            "authenticated_validation_lab_api",
            "skip",
            "set THREATGENIX_PROD_E2E_TOKEN for the read-only authenticated API check",
        )
    try:
        status, raw, _content_type = _request(
            _url(base_url, f"/api/threat-models/{threat_model_id}/validation-lab"),
            token=token,
        )
        body = _json_body(raw)
    except Exception as exc:
        return SmokeResult("authenticated_validation_lab_api", "fail", str(exc))
    if status != 200:
        return SmokeResult(
            "authenticated_validation_lab_api", "fail", f"HTTP {status}: {body}"
        )
    runtime = body.get("runtime")
    runner = body.get("runner_status")
    if not isinstance(runtime, dict) or not isinstance(runner, dict):
        return SmokeResult(
            "authenticated_validation_lab_api",
            "fail",
            "runtime or runner_status missing",
        )
    return SmokeResult(
        "authenticated_validation_lab_api",
        "pass",
        f"runtime={runtime.get('mode')} runner={runner.get('status')}",
    )


def check_synthetic_byok_save_delete(base_url: str, token: str) -> SmokeResult:
    """Exercise real BYOK persistence with a disposable non-provider dummy key."""
    provider = "anthropic"
    dummy_key = f"sk-ant-api03-codex-smoke-not-real-{secrets.token_hex(12)}"
    stored = False
    try:
        status, raw, _ = _request(
            _url(base_url, f"/api/llm/keys/{provider}"),
            token=token,
            method="PUT",
            json_body={
                "api_key": dummy_key,
                "model_override": "claude-opus-prod-smoke-not-called",
            },
        )
        body = _json_body(raw)
        if status != 200:
            return SmokeResult(
                "synthetic_byok_save_delete",
                "fail",
                f"PUT returned HTTP {status}: {body}",
            )
        serialized = json.dumps(body)
        if dummy_key in serialized:
            return SmokeResult(
                "synthetic_byok_save_delete", "fail", "PUT response leaked dummy key"
            )
        if body.get("provider") != provider or not body.get("masked_key"):
            return SmokeResult(
                "synthetic_byok_save_delete", "fail", f"unexpected PUT response: {body}"
            )
        stored = True

        list_status, list_raw, _ = _request(
            _url(base_url, "/api/llm/keys"), token=token
        )
        listed = _json_document(list_raw)
        if list_status != 200 or not isinstance(listed, list):
            return SmokeResult(
                "synthetic_byok_save_delete",
                "fail",
                f"GET returned HTTP {list_status}: {listed}",
            )
        if dummy_key in json.dumps(listed):
            return SmokeResult(
                "synthetic_byok_save_delete", "fail", "GET response leaked dummy key"
            )
        if not any(
            isinstance(item, dict) and item.get("provider") == provider
            for item in listed
        ):
            return SmokeResult(
                "synthetic_byok_save_delete", "fail", "stored BYOK key was not listed"
            )

        delete_status, _delete_raw, _ = _request(
            _url(base_url, f"/api/llm/keys/{provider}"),
            token=token,
            method="DELETE",
        )
        if delete_status != 204:
            return SmokeResult(
                "synthetic_byok_save_delete",
                "fail",
                f"DELETE returned HTTP {delete_status}",
            )
        stored = False

        final_status, final_raw, _ = _request(
            _url(base_url, "/api/llm/keys"), token=token
        )
        final_list = _json_document(final_raw)
        if final_status != 200 or not isinstance(final_list, list):
            return SmokeResult(
                "synthetic_byok_save_delete",
                "fail",
                f"final GET returned HTTP {final_status}: {final_list}",
            )
        if any(
            isinstance(item, dict) and item.get("provider") == provider
            for item in final_list
        ):
            return SmokeResult(
                "synthetic_byok_save_delete", "fail", "BYOK key remained after DELETE"
            )
        return SmokeResult(
            "synthetic_byok_save_delete",
            "pass",
            "dummy BYOK key saved, masked, listed, and deleted without provider test call",
        )
    except Exception as exc:
        return SmokeResult("synthetic_byok_save_delete", "fail", str(exc))
    finally:
        if stored:
            try:
                _request(
                    _url(base_url, f"/api/llm/keys/{provider}"),
                    token=token,
                    method="DELETE",
                )
            except Exception:
                pass


def check_synthetic_assistant_copilot(
    base_url: str, token: str, threat_model_id: str
) -> SmokeResult:
    """Submit a synthetic Ask AI/copilot prompt against a disposable model."""
    try:
        status, raw, _ = _request(
            _url(base_url, f"/api/threat-models/{threat_model_id}/assistant/respond"),
            token=token,
            method="POST",
            json_body={
                "mode_hint": "ask",
                "message": (
                    "For this synthetic production smoke model only, give one concise "
                    "threat-modeling observation. Do not request customer data."
                ),
            },
        )
        body = _json_body(raw)
        if status != 200:
            return SmokeResult(
                "synthetic_assistant_copilot",
                "fail",
                f"assistant returned HTTP {status}: {body}",
            )
        answer = body.get("answer")
        if not isinstance(answer, str) or not answer.strip():
            return SmokeResult(
                "synthetic_assistant_copilot", "fail", "assistant answer was empty"
            )
        degraded = body.get("degraded_reason")
        if degraded:
            return SmokeResult(
                "synthetic_assistant_copilot",
                "fail",
                f"assistant degraded instead of using the live provider: {degraded}",
            )
        return SmokeResult(
            "synthetic_assistant_copilot",
            "pass",
            f"assistant responded with mode={body.get('mode')} and a non-empty answer",
        )
    except Exception as exc:
        return SmokeResult("synthetic_assistant_copilot", "fail", str(exc))


def _synthetic_validation_target_archive() -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "app.py",
            (
                "import jwt\n\n"
                "def decode_token(token):\n"
                '    return jwt.decode(token, options={"verify_signature": False})\n'
            ),
        )
        archive.writestr(
            "main.tf",
            (
                'resource "aws_s3_bucket" "public" {\n'
                '  bucket = "threatgenix-prod-upload-smoke"\n'
                '  acl    = "public-read"\n'
                "}\n\n"
                'resource "aws_security_group" "open" {\n'
                '  name = "threatgenix-open"\n'
                "  ingress {\n"
                "    from_port   = 22\n"
                "    to_port     = 22\n"
                '    protocol    = "tcp"\n'
                '    cidr_blocks = ["0.0.0.0/0"]\n'
                "  }\n"
                "}\n"
            ),
        )
        archive.writestr(
            "requirements.txt",
            "Django==1.2\nPyYAML==3.13\n",
        )
    return buffer.getvalue()


def upload_synthetic_validation_target_bundle(
    base_url: str,
    *,
    token: str,
    threat_model_id: str,
) -> str:
    status, raw, _content_type = _request_multipart(
        _url(
            base_url,
            f"/api/threat-models/{threat_model_id}/validation-lab/target-bundles",
        ),
        token=token,
        fields={
            "name": "Codex production upload smoke",
            "authorization_acknowledged": "true",
        },
        file_field="file",
        filename="codex-validation-target.zip",
        file_content_type="application/zip",
        file_bytes=_synthetic_validation_target_archive(),
    )
    body = _json_body(raw)
    target_ref = body.get("target_ref")
    if status != 201 or not isinstance(target_ref, str) or not target_ref:
        raise RuntimeError(f"target bundle upload returned HTTP {status}: {body}")
    return target_ref


def _schedule_validation_run(
    base_url: str,
    *,
    token: str,
    threat_model_id: str,
    tool_name: str,
    target_type: str,
    target: str,
) -> tuple[int, dict[str, Any]]:
    return _post_json(
        base_url,
        f"/api/threat-models/{threat_model_id}/validation-lab/schedules",
        {
            "name": f"{tool_name} production smoke",
            "tool_name": tool_name,
            "target_type": target_type,
            "target": target,
            "scope": "external" if target_type == "url" else "internal",
            "cadence": "manual",
            "enabled": False,
            "authorization_acknowledged": True,
        },
        token=token,
    )


def _run_validation_schedule(
    base_url: str,
    *,
    token: str,
    threat_model_id: str,
    schedule_id: str,
) -> tuple[int, dict[str, Any]]:
    return _post_json(
        base_url,
        f"/api/threat-models/{threat_model_id}/validation-lab/schedules/{schedule_id}/run",
        {"authorization_acknowledged": True},
        token=token,
    )


def _get_scan_detail(
    base_url: str,
    *,
    token: str,
    threat_model_id: str,
    scan_id: str,
) -> tuple[int, dict[str, Any]]:
    status, raw, _content_type = _request(
        _url(base_url, f"/api/threat-models/{threat_model_id}/scans/{scan_id}"),
        token=token,
        timeout=60,
    )
    return status, _json_body(raw)


def _poll_scan_completion(
    base_url: str,
    *,
    token: str,
    threat_model_id: str,
    scan_id: str,
    timeout_seconds: float = 240.0,
    poll_interval_seconds: float = 2.0,
) -> tuple[str, dict[str, Any]]:
    deadline = time.monotonic() + timeout_seconds
    last_body: dict[str, Any] = {}
    while time.monotonic() < deadline:
        status, body = _get_scan_detail(
            base_url,
            token=token,
            threat_model_id=threat_model_id,
            scan_id=scan_id,
        )
        if status != 200:
            return "http_error", {"http_status": status, "body": body}
        last_body = body
        scan_status = str(body.get("status") or "")
        if scan_status in {"completed", "failed", "cancelled"}:
            return scan_status, body
        time.sleep(poll_interval_seconds)
    return "timeout", last_body


def _expected_managed_blocked_reason(reason: object) -> bool:
    if not isinstance(reason, str):
        return False
    normalized = reason.lower()
    return "disabled" in normalized and (
        "sandbox" in normalized or "isolation" in normalized or "isolated" in normalized
    )


def _expected_nuclei_authorization_block(detail: dict[str, Any]) -> bool:
    message = str(detail.get("error_message") or "").lower()
    return (
        str(detail.get("status") or "") == "failed"
        and "target ownership verification" in message
    )


def check_synthetic_validation_tool_runs(
    base_url: str,
    *,
    token: str,
    threat_model_id: str,
    validation_target: str,
) -> SmokeResult:
    """Run safe no-network validation tools against a pre-staged managed-worker path."""
    completed: list[str] = []
    failed: list[str] = []
    disabled: list[str] = []
    try:
        for tool_name, target_type in OFFLINE_VALIDATION_TOOL_CHECKS:
            schedule_status, schedule_body = _schedule_validation_run(
                base_url,
                token=token,
                threat_model_id=threat_model_id,
                tool_name=tool_name,
                target_type=target_type,
                target=validation_target,
            )
            schedule_id = schedule_body.get("id")
            if schedule_status != 201 or not isinstance(schedule_id, str):
                failed.append(
                    f"{tool_name}: schedule HTTP {schedule_status}: {schedule_body}"
                )
                continue
            if schedule_body.get("runnable") is not True:
                failed.append(
                    f"{tool_name}: schedule was not runnable: {schedule_body}"
                )
                continue
            run_status, run_body = _run_validation_schedule(
                base_url,
                token=token,
                threat_model_id=threat_model_id,
                schedule_id=schedule_id,
            )
            scan_id = run_body.get("id")
            if run_status != 201 or not isinstance(scan_id, str):
                failed.append(f"{tool_name}: run HTTP {run_status}: {run_body}")
                continue
            final_status, detail = _poll_scan_completion(
                base_url,
                token=token,
                threat_model_id=threat_model_id,
                scan_id=scan_id,
            )
            if final_status != "completed":
                failed.append(f"{tool_name}: {final_status}: {detail}")
                continue
            completed.append(f"{tool_name}={detail.get('finding_count', 0)} findings")

        osv_target = f"{validation_target}#requirements.txt"
        schedule_status, schedule_body = _schedule_validation_run(
            base_url,
            token=token,
            threat_model_id=threat_model_id,
            tool_name="osv-scanner",
            target_type="lockfile",
            target=osv_target,
        )
        schedule_id = schedule_body.get("id")
        if schedule_status != 201 or not isinstance(schedule_id, str):
            failed.append(f"osv-scanner: schedule HTTP {schedule_status}: {schedule_body}")
        elif schedule_body.get("runnable") is not True:
            failed.append(f"osv-scanner: schedule was not runnable: {schedule_body}")
        else:
            run_status, run_body = _run_validation_schedule(
                base_url,
                token=token,
                threat_model_id=threat_model_id,
                schedule_id=schedule_id,
            )
            scan_id = run_body.get("id")
            if run_status != 201 or not isinstance(scan_id, str):
                failed.append(f"osv-scanner: run HTTP {run_status}: {run_body}")
            else:
                final_status, detail = _poll_scan_completion(
                    base_url,
                    token=token,
                    threat_model_id=threat_model_id,
                    scan_id=scan_id,
                )
                if final_status != "completed":
                    failed.append(f"osv-scanner: {final_status}: {detail}")
                else:
                    completed.append(
                        f"osv-scanner={detail.get('finding_count', 0)} findings"
                    )

        for tool_name, target_type, configured_target in DISABLED_MANAGED_TOOL_CHECKS:
            schedule_status, schedule_body = _schedule_validation_run(
                base_url,
                token=token,
                threat_model_id=threat_model_id,
                tool_name=tool_name,
                target_type=target_type,
                target=configured_target or validation_target,
            )
            schedule_id = schedule_body.get("id")
            if schedule_status == 201 and schedule_body.get("runnable") is False:
                blocked_reason = str(schedule_body.get("blocked_reason") or "blocked")
                if not _expected_managed_blocked_reason(blocked_reason):
                    failed.append(
                        f"{tool_name}: unexpected blocked reason: {blocked_reason}"
                    )
                    continue
                disabled.append(f"{tool_name}: {blocked_reason}")
                continue
            if (
                tool_name == "nuclei"
                and schedule_status == 201
                and isinstance(schedule_id, str)
            ):
                run_status, run_body = _run_validation_schedule(
                    base_url,
                    token=token,
                    threat_model_id=threat_model_id,
                    schedule_id=schedule_id,
                )
                scan_id = run_body.get("id")
                if run_status != 201 or not isinstance(scan_id, str):
                    failed.append(f"{tool_name}: run HTTP {run_status}: {run_body}")
                    continue
                final_status, detail = _poll_scan_completion(
                    base_url,
                    token=token,
                    threat_model_id=threat_model_id,
                    scan_id=scan_id,
                )
                if not _expected_nuclei_authorization_block(detail):
                    failed.append(f"{tool_name}: expected target-auth block, got {final_status}: {detail}")
                    continue
                disabled.append(f"{tool_name}: target ownership verification enforced")
                continue
            failed.append(
                f"{tool_name}: expected fail-closed, got HTTP {schedule_status}: {schedule_body}"
            )

        if failed:
            return SmokeResult(
                "synthetic_validation_tool_runs", "fail", "; ".join(failed)
            )
        return SmokeResult(
            "synthetic_validation_tool_runs",
            "pass",
            "completed "
            + ", ".join(completed)
            + "; fail-closed "
            + ", ".join(disabled),
        )
    except Exception as exc:
        return SmokeResult("synthetic_validation_tool_runs", "fail", str(exc))


def check_synthetic_authenticated_journey(
    base_url: str,
    *,
    assistant_live: bool = False,
    validation_target: str | None = None,
    validation_upload: bool = False,
) -> SmokeResult:
    """Create a synthetic tenant/model and run the read-only authenticated API gate."""
    unique = f"{int(time.time())}-{secrets.token_hex(4)}"
    email = f"codex-prod-smoke-{unique}@example.com"
    password = f"TgxSmoke{secrets.token_urlsafe(18)}A1"
    try:
        register_status, register_body = _post_json(
            base_url,
            "/api/auth/register",
            {
                "email": email,
                "password": password,
                "full_name": "ThreatGenix Prod Smoke",
            },
        )
        if register_status != 201:
            return SmokeResult(
                "synthetic_authenticated_journey",
                "fail",
                f"register returned HTTP {register_status}: {register_body}",
            )

        login_status, login_body = _post_json(
            base_url,
            "/api/auth/login",
            {"email": email, "password": password},
        )
        token = login_body.get("access_token")
        if login_status != 200 or not isinstance(token, str) or not token:
            return SmokeResult(
                "synthetic_authenticated_journey",
                "fail",
                f"login returned HTTP {login_status} without a token",
            )

        me_status, me_raw, _ = _request(_url(base_url, "/api/auth/me"), token=token)
        me_body = _json_body(me_raw)
        if me_status != 200 or me_body.get("email") != email:
            return SmokeResult(
                "synthetic_authenticated_journey",
                "fail",
                f"/api/auth/me returned HTTP {me_status}: {me_body}",
            )

        model_status, model_body = _post_json(
            base_url,
            "/api/threat-models",
            {
                "system_name": f"Codex Prod Smoke {unique}",
                "description": "Synthetic production smoke model. Safe to delete.",
                "data_classification": "Internal",
                "regulatory_scope": ["NIST"],
                "deployment_model": "cloud",
            },
            token=token,
        )
        model_id = model_body.get("id")
        if model_status != 201 or not isinstance(model_id, str) or not model_id:
            return SmokeResult(
                "synthetic_authenticated_journey",
                "fail",
                f"threat-model create returned HTTP {model_status}: {model_body}",
            )

        lab_result = check_authenticated_validation_lab_api(base_url, model_id, token)
        if lab_result.status != "pass":
            return SmokeResult(
                "synthetic_authenticated_journey",
                "fail",
                f"Validation Lab API for synthetic model {model_id} failed: {lab_result.detail}",
            )
        byok_result = check_synthetic_byok_save_delete(base_url, token)
        if byok_result.status != "pass":
            return SmokeResult(
                "synthetic_authenticated_journey",
                "fail",
                f"BYOK smoke failed: {byok_result.detail}",
            )
        assistant_detail = "assistant/copilot not requested"
        if assistant_live:
            assistant_result = check_synthetic_assistant_copilot(
                base_url, token, model_id
            )
            if assistant_result.status != "pass":
                return SmokeResult(
                    "synthetic_authenticated_journey",
                    "fail",
                    f"assistant/copilot smoke failed: {assistant_result.detail}",
                )
            assistant_detail = "assistant/copilot passed"
        validation_detail = "validation tools not requested"
        if validation_upload:
            validation_target = upload_synthetic_validation_target_bundle(
                base_url,
                token=token,
                threat_model_id=model_id,
            )
        if validation_target:
            validation_result = check_synthetic_validation_tool_runs(
                base_url,
                token=token,
                threat_model_id=model_id,
                validation_target=validation_target,
            )
            if validation_result.status != "pass":
                return SmokeResult(
                    "synthetic_authenticated_journey",
                    "fail",
                    f"validation tool smoke failed: {validation_result.detail}",
                )
            validation_detail = validation_result.detail
        return SmokeResult(
            "synthetic_authenticated_journey",
            "pass",
            (
                f"created synthetic tenant {email}; model {model_id}; "
                f"{lab_result.detail}; BYOK save/delete passed; {assistant_detail}; "
                f"{validation_detail}"
            ),
        )
    except Exception as exc:
        return SmokeResult("synthetic_authenticated_journey", "fail", str(exc))


def run_smoke(
    base_url: str,
    threat_model_id: str,
    token: str | None,
    *,
    api_only: bool = False,
    synthetic_auth: bool = False,
    synthetic_assistant: bool = False,
    synthetic_validation_target: str | None = None,
    synthetic_validation_upload: bool = False,
    heartbeat_proof: bool = False,
    expected_source_version: str | None = None,
) -> list[SmokeResult]:
    results = [
        check_deep_health(base_url, expected_source_version=expected_source_version),
        check_unauthenticated_auth_gate(base_url),
        check_authenticated_validation_lab_api(base_url, threat_model_id, token),
    ]
    if api_only:
        results.insert(
            2,
            SmokeResult(
                "validation_lab_route",
                "skip",
                "API-only deployment; frontend SPA route is not served by this base URL",
            ),
        )
    else:
        results.insert(2, check_validation_lab_route(base_url, threat_model_id))
    if heartbeat_proof:
        results.append(check_runner_heartbeat_advances(base_url))
    if synthetic_auth:
        results.append(
            check_synthetic_authenticated_journey(
                base_url,
                assistant_live=synthetic_assistant,
                validation_target=synthetic_validation_target,
                validation_upload=synthetic_validation_upload,
            )
        )
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url", default=os.getenv("THREATGENIX_SAAS_BASE_URL", DEFAULT_BASE_URL)
    )
    parser.add_argument(
        "--threat-model-id",
        default=os.getenv("THREATGENIX_PROD_E2E_THREAT_MODEL_ID", DEFAULT_MODEL_ID),
    )
    parser.add_argument("--token", default=os.getenv("THREATGENIX_PROD_E2E_TOKEN"))
    parser.add_argument(
        "--expected-source-version",
        default=os.getenv("THREATGENIX_EXPECTED_SOURCE_VERSION"),
        help="Require /api/health?deep=true to report this SOURCE_VERSION.",
    )
    parser.add_argument(
        "--api-only",
        action="store_true",
        default=os.getenv("THREATGENIX_PROD_E2E_API_ONLY") == "1",
        help="Skip frontend SPA route checks when the base URL is an API-only deployment.",
    )
    parser.add_argument(
        "--synthetic-auth",
        action="store_true",
        default=os.getenv("THREATGENIX_PROD_E2E_SYNTHETIC_AUTH") == "1",
        help=(
            "Create a synthetic prod smoke user and model, then run the "
            "authenticated Validation Lab API gate without printing secrets."
        ),
    )
    parser.add_argument(
        "--heartbeat-proof",
        action="store_true",
        default=os.getenv("THREATGENIX_PROD_E2E_HEARTBEAT_PROOF") == "1",
        help="Wait for and verify the managed runner heartbeat advances.",
    )
    parser.add_argument(
        "--synthetic-assistant",
        action="store_true",
        default=os.getenv("THREATGENIX_PROD_E2E_SYNTHETIC_ASSISTANT") == "1",
        help=(
            "Also require the disposable synthetic journey to exercise the live "
            "assistant provider. Disabled by default so staging can pass without "
            "external AI billing."
        ),
    )
    parser.add_argument(
        "--synthetic-validation-target",
        default=os.getenv("THREATGENIX_PROD_E2E_VALIDATION_TARGET"),
        help=(
            "Run Semgrep, Trivy, Checkov, and TruffleHog against this pre-staged "
            "managed-worker filesystem path, and verify Nuclei/OSV fail closed. "
            "Requires --synthetic-auth."
        ),
    )
    parser.add_argument(
        "--synthetic-validation-upload",
        action="store_true",
        default=os.getenv("THREATGENIX_PROD_E2E_VALIDATION_UPLOAD") == "1",
        help=(
            "Upload a synthetic zip target through the hosted target-bundle API, "
            "then run the no-network scanner proof against the returned tgx-target ref. "
            "Requires --synthetic-auth."
        ),
    )
    args = parser.parse_args(argv)
    if (
        args.synthetic_validation_target or args.synthetic_validation_upload
    ) and not args.synthetic_auth:
        parser.error("--synthetic validation target/upload requires --synthetic-auth")
    if args.synthetic_validation_target and args.synthetic_validation_upload:
        parser.error(
            "--synthetic-validation-target and --synthetic-validation-upload are mutually exclusive"
        )

    results = run_smoke(
        args.base_url,
        args.threat_model_id,
        args.token,
        api_only=args.api_only,
        synthetic_auth=args.synthetic_auth,
        synthetic_assistant=args.synthetic_assistant,
        synthetic_validation_target=args.synthetic_validation_target,
        synthetic_validation_upload=args.synthetic_validation_upload,
        heartbeat_proof=args.heartbeat_proof,
        expected_source_version=args.expected_source_version,
    )
    print(json.dumps([asdict(result) for result in results], indent=2))
    return 1 if any(result.status == "fail" for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
