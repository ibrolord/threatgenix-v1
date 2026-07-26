from __future__ import annotations

import json
import sys
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.models.scan import ScanExecutionArtifact, ScanFinding
from app.services.scan_worker import _scan_target
from app.services.validation_execution_policy import (
    TARGET_LOCKFILE,
    TARGET_REPOSITORY_PATH,
    TARGET_URL,
    build_validation_tool_inventory,
    default_validation_execution_policy_registry,
    validation_tool_runtime_availability,
)
from app.services.validation_isolated_runner import (
    IsolatedRunnerConfigurationError,
    KubectlIsolatedRunnerClient,
    _CommandResult,
    _kubernetes_collection_path,
    _kubernetes_job_condition,
    _kubernetes_pod_logs_path,
    _pod_scanner_exit_code,
    _normalized_tool_returncode,
    _run_command,
    build_isolated_validation_job_spec,
    build_kubernetes_manifest_objects,
    build_nuclei_target_network_grant,
    run_isolated_validation_tool,
)
from app.services.validation_sandbox import (
    VALIDATION_ALLOWED_PATHS_ENV,
    VALIDATION_ISOLATED_RUNNER_BACKEND_ENV,
    VALIDATION_ISOLATED_RUNNER_EGRESS_PROXY_ENV,
    VALIDATION_ISOLATED_RUNNER_PROOF_ENV,
)
from app.services.validation_tools import (
    NucleiValidationAdapter,
    OSVScannerValidationAdapter,
    ValidationEvidence,
    ValidationToolResult,
    ValidationToolUnavailable,
)


def _enable_isolated_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "staging")
    monkeypatch.setenv(VALIDATION_ISOLATED_RUNNER_BACKEND_ENV, "gke")
    monkeypatch.setenv(
        VALIDATION_ISOLATED_RUNNER_EGRESS_PROXY_ENV,
        "http://threatgenix-egress-proxy:8080",
    )
    monkeypatch.setenv(
        VALIDATION_ISOLATED_RUNNER_PROOF_ENV,
        "deploy/gcp/isolated-runner/README.md",
    )
    monkeypatch.setenv("THREATGENIX_VALIDATION_K8S_API_SERVER", "https://1.2.3.4")
    monkeypatch.setenv("THREATGENIX_VALIDATION_K8S_CA_CERT_B64", "LS0tQ0EtLS0t")
    monkeypatch.setenv(
        "THREATGENIX_VALIDATION_ISOLATED_IMAGE_NUCLEI",
        "us-docker.pkg.dev/project/scanners/nuclei-runner@sha256:" + "a" * 64,
    )
    monkeypatch.setenv(
        "THREATGENIX_VALIDATION_ISOLATED_IMAGE_OSV_SCANNER",
        "us-docker.pkg.dev/project/scanners/osv-runner@sha256:" + "b" * 64,
    )
    monkeypatch.setenv("THREATGENIX_VALIDATION_OSV_SCANNER_ENABLED", "true")
    monkeypatch.setenv(
        "THREATGENIX_VALIDATION_NUCLEI_REQUIRE_TARGET_VERIFICATION",
        "true",
    )


def test_nuclei_network_grant_pins_public_ipv4_and_target_host():
    grant = build_nuclei_target_network_grant(
        "https://scan.example.com/login",
        proxy_url="http://proxy:8080",
        resolver=lambda host, port: ["8.8.8.8"],
    )

    assert grant.mode == "target_only"
    assert grant.allowed_hosts == ("scan.example.com",)
    assert grant.allowed_cidrs == ("8.8.8.8/32",)
    assert grant.allowed_ports == (443,)


def test_nuclei_network_grant_rejects_private_dns_rebinding():
    with pytest.raises(ValueError, match="globally routable"):
        build_nuclei_target_network_grant(
            "https://scan.example.com",
            proxy_url="http://proxy:8080",
            resolver=lambda host, port: ["10.0.0.5"],
        )


def test_nuclei_network_grant_rejects_carrier_grade_nat():
    with pytest.raises(ValueError, match="globally routable"):
        build_nuclei_target_network_grant(
            "https://scan.example.com",
            proxy_url="http://proxy:8080",
            resolver=lambda host, port: ["100.64.0.1"],
        )


def test_nuclei_network_grant_rejects_ipv6_without_explicit_controls():
    with pytest.raises(ValueError, match="IPv6"):
        build_nuclei_target_network_grant(
            "https://scan.example.com",
            proxy_url="http://proxy:8080",
            resolver=lambda host, port: ["2606:4700:4700::1111"],
        )


def test_nuclei_isolated_spec_rejects_url_credentials(monkeypatch):
    _enable_isolated_runner(monkeypatch)
    policy = default_validation_execution_policy_registry().get("nuclei")
    adapter = NucleiValidationAdapter()

    with pytest.raises(ValueError, match="credentials"):
        build_isolated_validation_job_spec(
            scan_job_id=uuid4(),
            threat_model_id=uuid4(),
            owner_id=uuid4(),
            tool=adapter,
            target="https://user:pass@scan.example.com",
            target_type=TARGET_URL,
            policy=policy,
            command=adapter.build_command("https://user:pass@scan.example.com"),
            resolver=lambda host, port: ["8.8.8.8"],
        )


def test_nuclei_isolated_spec_rejects_auth_headers_until_broker_exists(monkeypatch):
    _enable_isolated_runner(monkeypatch)
    policy = default_validation_execution_policy_registry().get("nuclei")
    adapter = NucleiValidationAdapter()

    with pytest.raises(IsolatedRunnerConfigurationError, match="credential broker"):
        build_isolated_validation_job_spec(
            scan_job_id=uuid4(),
            threat_model_id=uuid4(),
            owner_id=uuid4(),
            tool=adapter,
            target="https://scan.example.com",
            target_type=TARGET_URL,
            policy=policy,
            command=adapter.build_command(
                "https://scan.example.com",
                auth_headers=["-H", "Authorization: Bearer secret"],
            ),
            auth_headers=["-H", "Authorization: Bearer secret"],
            resolver=lambda host, port: ["8.8.8.8"],
        )


def test_nuclei_manifest_uses_proxy_secret_without_pod_spec_token(monkeypatch):
    _enable_isolated_runner(monkeypatch)
    policy = default_validation_execution_policy_registry().get("nuclei")
    adapter = NucleiValidationAdapter()

    spec = build_isolated_validation_job_spec(
        scan_job_id=uuid4(),
        threat_model_id=uuid4(),
        owner_id=uuid4(),
        tool=adapter,
        target="http://scan.example.com",
        target_type=TARGET_URL,
        policy=policy,
        command=adapter.build_command("http://scan.example.com"),
        resolver=lambda host, port: ["8.8.8.8"],
    )
    objects = build_kubernetes_manifest_objects(spec)
    job = next(item for item in objects if item["kind"] == "Job")
    proxy_secret = next(
        item for item in objects
        if item["kind"] == "Secret" and item["metadata"]["name"].endswith("-proxy")
    )
    container = job["spec"]["template"]["spec"]["containers"][0]
    env = {item["name"]: item["value"] for item in container["env"]}
    command = json.loads(env["TG_COMMAND_JSON"])

    assert "-proxy" not in command
    assert spec.proxy_token not in env["TG_COMMAND_JSON"]
    assert env["TG_PROXY_BASE_URL"] == "http://threatgenix-egress-proxy:8080"
    assert env["TG_PROXY_USERNAME"] == spec.job_name
    assert env["TG_PROXY_TOKEN_FILE"] == "/etc/threatgenix/proxy/token"
    assert proxy_secret["stringData"]["token"] == spec.proxy_token


def test_osv_lockfile_manifest_mounts_input_readonly_and_allows_only_proxy(
    monkeypatch,
    tmp_path,
):
    _enable_isolated_runner(monkeypatch)
    monkeypatch.setenv(VALIDATION_ALLOWED_PATHS_ENV, str(tmp_path))
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text('{"lockfileVersion": 3, "packages": {}}\n')
    adapter = OSVScannerValidationAdapter()
    policy = default_validation_execution_policy_registry().get("osv-scanner")

    spec = build_isolated_validation_job_spec(
        scan_job_id=uuid4(),
        threat_model_id=uuid4(),
        owner_id=uuid4(),
        tool=adapter,
        target=str(lockfile),
        target_type=TARGET_LOCKFILE,
        policy=policy,
        command=adapter.build_command(str(lockfile), target_type=TARGET_LOCKFILE),
    )
    objects = build_kubernetes_manifest_objects(spec)
    job = next(item for item in objects if item["kind"] == "Job")
    network_policy = next(item for item in objects if item["kind"] == "NetworkPolicy")
    egress_config = next(
        item for item in objects
        if item["kind"] == "ConfigMap" and item["metadata"]["name"].endswith("-egress-cm")
    )
    target_config = next(
        item for item in objects
        if item["kind"] == "ConfigMap" and item["metadata"]["name"].endswith("-target")
    )
    container = job["spec"]["template"]["spec"]["containers"][0]
    env = {item["name"]: item["value"] for item in container["env"]}

    assert target_config["data"]["package-lock.json"].startswith("{")
    assert job["spec"]["template"]["spec"]["automountServiceAccountToken"] is False
    assert job["spec"]["template"]["spec"]["securityContext"]["fsGroup"] == 65532
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["resources"]["requests"] == container["resources"]["limits"]
    assert any(
        mount["mountPath"] == "/workspace/target" and mount["readOnly"] is True
        for mount in container["volumeMounts"]
    )
    assert "DATABASE_URL" not in env
    assert "SECRET_KEY" not in env
    assert env["HOME"] == "/tmp"
    assert env["TG_PROXY_BASE_URL"] == "http://threatgenix-egress-proxy:8080"
    assert env["TG_PROXY_USERNAME"] == spec.job_name
    assert env["TG_PROXY_TOKEN_FILE"] == "/etc/threatgenix/proxy/token"
    assert "HTTPS_PROXY" not in env
    assert "HTTP_PROXY" not in env
    assert env["no_proxy"] == env["NO_PROXY"]
    assert any(
        mount["mountPath"] == "/etc/threatgenix/proxy" and mount["readOnly"] is True
        for mount in container["volumeMounts"]
    )
    assert any(
        volume["name"] == "proxy-token"
        and volume["secret"]["secretName"] == f"{spec.job_name}-proxy"
        and volume["secret"]["defaultMode"] == 0o440
        for volume in job["spec"]["template"]["spec"]["volumes"]
    )
    policy = json.loads(egress_config["data"].get("policy.json", "{}"))
    assert policy["proxy_token_sha256"]
    assert str(tmp_path) not in env["TG_COMMAND_JSON"]
    assert "/workspace/target/package-lock.json" in env["TG_COMMAND_JSON"]
    assert network_policy["spec"]["ingress"] == []
    assert len(network_policy["spec"]["egress"]) == 3


def test_kubernetes_api_helpers_extract_status_and_paths():
    assert (
        _kubernetes_collection_path(
            {"apiVersion": "batch/v1", "kind": "Job"},
            namespace="threatgenix-validation",
        )
        == "/apis/batch/v1/namespaces/threatgenix-validation/jobs"
    )
    assert (
        _kubernetes_job_condition(
            {"status": {"conditions": [{"type": "Complete", "status": "True"}]}}
        )
        == "Complete"
    )
    log_path = _kubernetes_pod_logs_path(
        namespace="threatgenix-validation",
        pod_name="tg-scan-test-pod",
        container="scanner",
        limit_bytes=1500001,
    )
    assert log_path == (
        "/api/v1/namespaces/threatgenix-validation/pods/"
        "tg-scan-test-pod/log?container=scanner&limitBytes=1500001"
    )
    assert "tailLines" not in log_path
    assert (
        _pod_scanner_exit_code(
            {
                "status": {
                    "containerStatuses": [
                        {"name": "scanner", "state": {"terminated": {"exitCode": 1}}}
                    ]
                }
            }
        )
        == 1
    )


def test_osv_repository_path_blocks_until_object_store_delivery(monkeypatch, tmp_path):
    _enable_isolated_runner(monkeypatch)
    monkeypatch.setenv(VALIDATION_ALLOWED_PATHS_ENV, str(tmp_path))
    repo = tmp_path / "repo"
    repo.mkdir()
    adapter = OSVScannerValidationAdapter()
    policy = default_validation_execution_policy_registry().get("osv-scanner")

    with pytest.raises(IsolatedRunnerConfigurationError, match="object-store"):
        build_isolated_validation_job_spec(
            scan_job_id=uuid4(),
            threat_model_id=uuid4(),
            owner_id=uuid4(),
            tool=adapter,
            target=str(repo),
            target_type=TARGET_REPOSITORY_PATH,
            policy=policy,
            command=adapter.build_command(
                str(repo),
                target_type=TARGET_REPOSITORY_PATH,
            ),
        )


@pytest.mark.asyncio
async def test_kubectl_runner_polls_until_job_finished(monkeypatch, tmp_path):
    _enable_isolated_runner(monkeypatch)
    monkeypatch.setenv(VALIDATION_ALLOWED_PATHS_ENV, str(tmp_path))
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text('{"lockfileVersion": 3, "packages": {}}\n')
    adapter = OSVScannerValidationAdapter()
    policy = default_validation_execution_policy_registry().get("osv-scanner")
    spec = build_isolated_validation_job_spec(
        scan_job_id=uuid4(),
        threat_model_id=uuid4(),
        owner_id=uuid4(),
        tool=adapter,
        target=str(lockfile),
        target_type=TARGET_LOCKFILE,
        policy=policy,
        command=adapter.build_command(str(lockfile), target_type=TARGET_LOCKFILE),
    )
    calls = []

    async def fake_run_command(command, *, input_text=None, timeout_seconds=120):
        del input_text
        calls.append((command, timeout_seconds))
        if "get" in command and "job" in command:
            return _CommandResult(
                returncode=0,
                stdout=json.dumps({"status": {"conditions": [{"type": "Complete", "status": "True"}]}}),
                stderr="",
            )
        if "get" in command and "pod" in command:
            return _CommandResult(returncode=0, stdout="0", stderr="")
        return _CommandResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "app.services.validation_isolated_runner._kubectl_path",
        lambda: "/usr/local/bin/kubectl",
    )
    monkeypatch.setattr(
        "app.services.validation_isolated_runner._run_command",
        fake_run_command,
    )

    await KubectlIsolatedRunnerClient().run(spec, adapter)

    assert any("job" in call[0] and "-o=json" in call[0] for call in calls)
    assert not any("wait" in call[0] for call in calls)


@pytest.mark.asyncio
async def test_kubectl_runner_requires_terminated_exit_code(monkeypatch, tmp_path):
    _enable_isolated_runner(monkeypatch)
    monkeypatch.setenv(VALIDATION_ALLOWED_PATHS_ENV, str(tmp_path))
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text('{"lockfileVersion": 3, "packages": {}}\n')
    adapter = OSVScannerValidationAdapter()
    policy = default_validation_execution_policy_registry().get("osv-scanner")
    spec = build_isolated_validation_job_spec(
        scan_job_id=uuid4(),
        threat_model_id=uuid4(),
        owner_id=uuid4(),
        tool=adapter,
        target=str(lockfile),
        target_type=TARGET_LOCKFILE,
        policy=policy,
        command=adapter.build_command(str(lockfile), target_type=TARGET_LOCKFILE),
    )

    async def fake_run_command(command, *, input_text=None, timeout_seconds=120):
        del input_text, timeout_seconds
        if "get" in command and "job" in command:
            return _CommandResult(
                returncode=0,
                stdout=json.dumps({"status": {"conditions": [{"type": "Complete", "status": "True"}]}}),
                stderr="",
            )
        if "get" in command and "pod" in command:
            return _CommandResult(returncode=0, stdout="", stderr="")
        return _CommandResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "app.services.validation_isolated_runner._kubectl_path",
        lambda: "/usr/local/bin/kubectl",
    )
    monkeypatch.setattr(
        "app.services.validation_isolated_runner._run_command",
        fake_run_command,
    )

    with pytest.raises(ValidationToolUnavailable, match="terminated scanner exit code"):
        await KubectlIsolatedRunnerClient().run(spec, adapter)


def test_isolated_runner_requires_digest_pinned_images_in_staging(monkeypatch):
    _enable_isolated_runner(monkeypatch)
    monkeypatch.setenv("THREATGENIX_VALIDATION_ISOLATED_IMAGE_NUCLEI", "nuclei:latest")
    policy = default_validation_execution_policy_registry().get("nuclei")
    adapter = NucleiValidationAdapter()

    with pytest.raises(IsolatedRunnerConfigurationError, match="digest"):
        build_isolated_validation_job_spec(
            scan_job_id=uuid4(),
            threat_model_id=uuid4(),
            owner_id=uuid4(),
            tool=adapter,
            target="https://scan.example.com",
            target_type=TARGET_URL,
            policy=policy,
            command=adapter.build_command("https://scan.example.com"),
            resolver=lambda host, port: ["8.8.8.8"],
        )


def test_osv_exit_code_one_normalizes_to_success_for_findings():
    assert (
        _normalized_tool_returncode(
            OSVScannerValidationAdapter(),
            exit_code=1,
            wait_returncode=1,
        )
        == 0
    )


@pytest.mark.asyncio
async def test_run_command_kills_timed_out_child():
    result = await _run_command(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout_seconds=1,
    )

    assert result.returncode == -1
    assert "timed out" in result.stderr


def test_tool_inventory_marks_osv_ready_with_isolated_runner(monkeypatch, tmp_path):
    _enable_isolated_runner(monkeypatch)
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", "true")
    monkeypatch.setenv(VALIDATION_ALLOWED_PATHS_ENV, str(tmp_path))

    items = {item.name: item for item in build_validation_tool_inventory()}
    osv = items["osv-scanner"]

    assert osv.runtime_strategy == "isolated_runner"
    assert osv.available is True
    assert osv.readiness_status == "ready"
    assert not any("isolated network runner" in reason for reason in osv.blocker_reasons)


def test_runtime_availability_does_not_advertise_isolated_runner_outside_managed(
    monkeypatch,
):
    _enable_isolated_runner(monkeypatch)
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")

    availability = validation_tool_runtime_availability(OSVScannerValidationAdapter())

    assert availability.strategy != "isolated_runner"


@pytest.mark.asyncio
async def test_run_isolated_nuclei_requires_authorization_check(monkeypatch):
    _enable_isolated_runner(monkeypatch)
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    adapter = NucleiValidationAdapter()

    with pytest.raises(IsolatedRunnerConfigurationError, match="target authorization"):
        await run_isolated_validation_tool(
            scan_job_id=uuid4(),
            threat_model_id=uuid4(),
            owner_id=uuid4(),
            tool=adapter,
            target="https://scan.example.com",
            target_type=TARGET_URL,
            policy=default_validation_execution_policy_registry().get("nuclei"),
        )


@pytest.mark.asyncio
async def test_scan_worker_routes_networked_tool_to_isolated_runner(monkeypatch):
    _enable_isolated_runner(monkeypatch)
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setattr(
        "app.services.scan_worker.validate_live_url_target",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "app.services.scan_worker.require_verified_nuclei_target_authorization",
        AsyncMock(return_value=None),
    )
    evidence = ValidationEvidence(
        tool_name="nuclei",
        target="https://scan.example.com",
        severity="medium",
        finding_title="test finding",
        cve_ids=[],
        tags=["test"],
        matched_url="https://scan.example.com",
        raw_output={"template-id": "test-template"},
        template_id="test-template",
    )
    isolated_run = AsyncMock(
        return_value=ValidationToolResult(
            tool_name="nuclei",
            target="https://scan.example.com",
            findings=[evidence],
            command=["nuclei", "-u", "https://scan.example.com"],
            resolved_target="https://scan.example.com",
            sandboxed=True,
            sandbox_mode="isolated-kubernetes",
            container_image="nuclei@sha256:" + "a" * 64,
            network_policy="target_only",
            resource_limits={"cpu": "1", "memory": "1Gi"},
        )
    )
    monkeypatch.setattr(
        "app.services.scan_worker.run_isolated_validation_tool",
        isolated_run,
    )

    class DB:
        def __init__(self) -> None:
            self.added = []
            self.commit = AsyncMock()

        def add(self, item):
            self.added.append(item)

    db = DB()
    findings = await _scan_target(
        db,  # type: ignore[arg-type]
        uuid4(),
        "https://scan.example.com",
        "direct",
        threat_model_id=uuid4(),
        owner_id=uuid4(),
        tool=NucleiValidationAdapter(),
        target_type=TARGET_URL,
        policy=default_validation_execution_policy_registry().get("nuclei"),
    )

    assert isolated_run.await_count == 1
    assert len(findings) == 1
    assert any(isinstance(item, ScanFinding) for item in db.added)
    artifact = next(item for item in db.added if isinstance(item, ScanExecutionArtifact))
    assert artifact.sandbox_mode == "isolated-kubernetes"
    assert artifact.network_mode == "target_only"
