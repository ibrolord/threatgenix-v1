# ThreatGenix v1

ThreatGenix is an open-source security review workbench for turning architecture
evidence into a reviewable threat model.

It combines a data-flow diagram editor, deterministic STRIDE rules, evidence
imports, analyst review workflows, optional AI-assisted analysis, and exportable
reports in one local application.

> [!IMPORTANT]
> This v1 release is a research preview. It is not a replacement for a
> penetration test, an application-security review, or human security judgment.
> Review every generated finding before using it in a security decision.

## What is included

- Interactive DFD modeling with components, flows, and trust boundaries
- Deterministic STRIDE threat generation
- Repository, IaC, cloud posture, and scanner-evidence imports
- Analyst decisions, risk acceptance, validation state, and report exports
- Optional LLM providers, including local Ollama and bring-your-own API keys
- A curated Try Sandbox for exploring the workflow without executing live scans

## Safety defaults

ThreatGenix starts in `try_sandbox` mode. Live scanner execution is disabled.

Live Nuclei scans require all of the following:

1. A managed isolated runner with digest-pinned images
2. Target-only egress enforcement
3. Proof of control bound to the exact target origin

Authenticated live scans are disabled in v1 because the isolated credential
broker is not implemented. Credentials are never passed to scanner processes in
command-line arguments.

See [managed runner readiness](docs/operations/managed-validation-runner-readiness.md)
for the deployment boundary.

## Quick start

Requirements:

- Docker with Compose
- 4 GB of free memory

```bash
git clone https://github.com/ibrolord/threatgenix-v1.git
cd threatgenix-v1
cp .env.example backend/.env
docker compose up --build
```

Open [http://localhost:5173](http://localhost:5173). The API is available at
[http://localhost:8000](http://localhost:8000).

The example configuration is for local development only. Before any production
or staging deployment, replace `SECRET_KEY`, `SCAN_CREDENTIAL_KEY`, and
`BYOK_ENCRYPTION_KEY` with independent secrets. Both encryption keys must be
base64-encoded 32-byte values.

## Local development

Backend:

```bash
docker compose up -d db
python3 -m venv backend/.venv
backend/.venv/bin/pip install -r backend/requirements.txt
cp .env.example backend/.env
cd backend
.venv/bin/alembic upgrade head
.venv/bin/uvicorn app.main:app --reload --port 8000
```

Frontend, in another terminal:

```bash
cd frontend
npm ci
npm run dev
```

## Verification

```bash
cd backend
python -m pytest -q
ruff check .

cd ../frontend
npm test
npm run typecheck
npm run lint
npm run build
```

## Responsible use

Only scan systems you own or are explicitly authorized to test. The
acknowledgment in the UI is not a substitute for written authorization.

Please report security issues privately using the process in
[SECURITY.md](SECURITY.md).

## Project status

This repository preserves the first complete ThreatGenix product shell as an
open-source v1. The project is useful for research, local evaluation, and
community collaboration. Interfaces and migrations may change before a stable
release.

## Contributing

Issues and focused pull requests are welcome. Read
[CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change.

## License

[MIT](LICENSE)
