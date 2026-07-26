from __future__ import annotations

from pathlib import Path

from app.services.deployment_preflight import (
    STATUS_CONFIGURATION_NEEDED,
    STATUS_FAIL,
    STATUS_PASS,
    check_fly_deployment_config,
    check_gcp_deployment_config,
)


APP_ROOT = Path(__file__).resolve().parents[1]


def test_fly_preflight_passes_checked_in_process_worker_config():
    result = check_fly_deployment_config(
        APP_ROOT / "fly.toml",
        environ={"FLY_API_TOKEN": "test-token"},
    )

    assert result.status == STATUS_PASS
    checks = {check.name: check for check in result.checks}
    assert checks["fly app process"].status == STATUS_PASS
    assert checks["fly worker process"].status == STATUS_PASS
    assert checks["fly public service process"].status == STATUS_PASS
    assert checks["fly process advisory DB egress"].status == STATUS_PASS
    assert "fly Nuclei sandbox mode" not in checks
    assert "fly OSV sandbox mode" not in checks


def test_fly_preflight_passes_sample_config_with_isolation_proof(tmp_path):
    fly_config = tmp_path / "fly.toml"
    fly_config.write_text(
        """
app = "threatgenix-api"

[processes]
  app = "uvicorn app.main:app --host 0.0.0.0 --port 8000"
  worker = "python worker_main.py"

[deploy]
  release_command = "sh scripts/migrate.sh"

[[services]]
  processes = ["app"]
  internal_port = 8000
  protocol = "tcp"

[env]
  APP_ENV = "staging"
  THREATGENIX_VALIDATION_RUNTIME_MODE = "managed"
  THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED = "true"
  THREATGENIX_VALIDATION_ALLOWED_PATHS = "/tmp/threatgenix-validation-targets"
  THREATGENIX_VALIDATION_OSV_SCANNER_ENABLED = "true"
  THREATGENIX_VALIDATION_SANDBOX_MODE = "container"
  THREATGENIX_VALIDATION_CONTAINER_RUNTIME = "docker"
  THREATGENIX_VALIDATION_CONTAINER_NETWORK = "threatgenix-advisory-egress"
  THREATGENIX_VALIDATION_CONTAINER_ISOLATION_PROOF = "deploy/fly/validation-runner-isolation.md"
""".strip()
    )

    result = check_fly_deployment_config(
        fly_config,
        environ={"FLY_API_TOKEN": "test-token"},
    )

    assert result.status == STATUS_PASS
    checks = {check.name: check for check in result.checks}
    assert checks["fly OSV isolation proof"].status == STATUS_PASS


def test_fly_preflight_marks_missing_deploy_token_configuration_needed():
    result = check_fly_deployment_config(APP_ROOT / "fly.toml", environ={})

    assert result.status == STATUS_CONFIGURATION_NEEDED
    checks = {check.name: check for check in result.checks}
    assert checks["fly deployment credentials"].status == STATUS_CONFIGURATION_NEEDED
    assert "FLY_API_TOKEN" in checks["fly deployment credentials"].detail


def test_fly_preflight_fails_process_sandbox_advisory_db_egress(tmp_path):
    fly_config = tmp_path / "fly.toml"
    fly_config.write_text(
        """
app = "threatgenix-api"

[processes]
  app = "uvicorn app.main:app --host 0.0.0.0 --port 8000"
  worker = "python worker_main.py"

[deploy]
  release_command = "sh scripts/migrate.sh"

[[services]]
  processes = ["app"]
  internal_port = 8000
  protocol = "tcp"

[env]
  APP_ENV = "staging"
  THREATGENIX_VALIDATION_RUNTIME_MODE = "managed"
  THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED = "true"
  THREATGENIX_VALIDATION_ALLOWED_PATHS = "/tmp/threatgenix-validation-targets"
  THREATGENIX_VALIDATION_OSV_SCANNER_ENABLED = "true"
  THREATGENIX_VALIDATION_SANDBOX_MODE = "process"
  THREATGENIX_VALIDATION_PROCESS_ADVISORY_DB_NETWORK = "true"
""".strip()
    )

    result = check_fly_deployment_config(
        fly_config,
        environ={"FLY_API_TOKEN": "test-token"},
    )

    assert result.status == STATUS_FAIL
    checks = {check.name: check for check in result.checks}
    assert checks["fly process advisory DB egress"].status == STATUS_FAIL
    assert "Process-sandbox advisory DB egress" in checks["fly process advisory DB egress"].detail


def test_gcp_preflight_marks_missing_config_configuration_needed(tmp_path):
    result = check_gcp_deployment_config(tmp_path, environ={})

    assert result.status == STATUS_CONFIGURATION_NEEDED
    assert result.checks[0].name == "gcp config present"
    assert "No GCP deployment config" in result.checks[0].detail


def test_gcp_preflight_passes_sample_staging_config_with_credentials(tmp_path):
    (tmp_path / "cloudbuild.yaml").write_text(
        """
steps:
  - name: gcr.io/google.com/cloudsdktool/cloud-sdk
    args:
      - run
      - deploy
      - threatgenix-api
      - --command=uvicorn app.main:app
      - --set-env-vars=APP_ENV=staging,THREATGENIX_VALIDATION_RUNTIME_MODE=managed,THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED=true,THREATGENIX_VALIDATION_ALLOWED_PATHS=/tmp/threatgenix-validation-targets,THREATGENIX_VALIDATION_OSV_SCANNER_ENABLED=true,THREATGENIX_VALIDATION_SANDBOX_MODE=container,THREATGENIX_VALIDATION_CONTAINER_RUNTIME=docker,THREATGENIX_VALIDATION_CONTAINER_NETWORK=threatgenix-advisory-egress,THREATGENIX_VALIDATION_CONTAINER_ISOLATION_PROOF=deploy/gcp/validation-runner-isolation.md
  - name: gcr.io/google.com/cloudsdktool/cloud-sdk
    args:
      - run
      - deploy
      - threatgenix-worker
      - --command=python worker_main.py
""".strip()
    )

    result = check_gcp_deployment_config(
        tmp_path,
        environ={
            "GOOGLE_CLOUD_PROJECT": "threatgenix-staging",
            "GOOGLE_APPLICATION_CREDENTIALS": "/tmp/fake-service-account.json",
        },
    )

    assert result.status == STATUS_PASS
    checks = {check.name: check for check in result.checks}
    assert checks["gcp api service command"].status == STATUS_PASS
    assert checks["gcp worker service command"].status == STATUS_PASS
    assert checks["gcp OSV sandbox mode"].status == STATUS_PASS
    assert checks["gcp deployment credentials"].status == STATUS_PASS


def test_gcp_preflight_passes_isolated_runner_config_with_digest_images(tmp_path):
    (tmp_path / "cloudbuild.yaml").write_text(
        """
steps:
  - name: gcr.io/google.com/cloudsdktool/cloud-sdk
    args:
      - run
      - deploy
      - threatgenix-api
      - --command=uvicorn app.main:app
      - --set-env-vars=APP_ENV=staging,THREATGENIX_VALIDATION_RUNTIME_MODE=managed,THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED=true,THREATGENIX_VALIDATION_ALLOWED_PATHS=/tmp/threatgenix-validation-targets,THREATGENIX_VALIDATION_NUCLEI_ENABLED=true,THREATGENIX_VALIDATION_OSV_SCANNER_ENABLED=true,THREATGENIX_VALIDATION_ISOLATED_RUNNER_BACKEND=gke,THREATGENIX_VALIDATION_ISOLATED_EGRESS_PROXY_URL=http://threatgenix-egress-proxy:8080,THREATGENIX_VALIDATION_K8S_API_SERVER=https://1.2.3.4,THREATGENIX_VALIDATION_K8S_CA_CERT_B64=LS0tQ0EtLS0t,THREATGENIX_VALIDATION_ISOLATED_IMAGE_NUCLEI=us-docker.pkg.dev/project/scanners/nuclei-runner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,THREATGENIX_VALIDATION_ISOLATED_IMAGE_OSV_SCANNER=us-docker.pkg.dev/project/scanners/osv-runner@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,THREATGENIX_VALIDATION_CONTAINER_ISOLATION_PROOF=deploy/gcp/isolated-runner/README.md,THREATGENIX_VALIDATION_NUCLEI_REQUIRE_TARGET_VERIFICATION=true
  - name: gcr.io/google.com/cloudsdktool/cloud-sdk
    args:
      - run
      - deploy
      - threatgenix-worker
      - --command=python worker_main.py
""".strip()
    )

    result = check_gcp_deployment_config(
        tmp_path,
        environ={
            "GOOGLE_CLOUD_PROJECT": "threatgenix-staging",
            "GOOGLE_APPLICATION_CREDENTIALS": "/tmp/fake-service-account.json",
        },
    )

    assert result.status == STATUS_PASS
    checks = {check.name: check for check in result.checks}
    assert checks["gcp isolated runner backend"].status == STATUS_PASS
    assert checks["gcp isolated egress proxy"].status == STATUS_PASS
    assert checks["gcp isolated Kubernetes API server"].status == STATUS_PASS
    assert checks["gcp isolated Kubernetes CA certificate"].status == STATUS_PASS
    assert checks["gcp Nuclei isolated image"].status == STATUS_PASS
    assert checks["gcp OSV isolated image"].status == STATUS_PASS
    assert checks["gcp Nuclei target verification required"].status == STATUS_PASS
