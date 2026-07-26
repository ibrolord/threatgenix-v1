.PHONY: dev dev-db dev-backend dev-frontend test test-backend test-frontend lint migrate seed clean reset-db eval-threat-modeler prepare-environment-evidence-fixtures claude-prompt

MODEL ?= opus

# Development
dev: dev-db dev-backend dev-frontend

dev-db:
	docker compose up -d db

dev-backend: migrate
	cd backend && uvicorn app.main:app --reload --port 8000

dev-frontend:
	cd frontend && npm run dev

# Testing
test: test-backend test-frontend

test-backend:
	cd backend && python -m pytest -v

test-frontend:
	cd frontend && npx tsc --noEmit

eval-threat-modeler:
	cd backend && python -m tests.evals.run_threat_modeler_audit --manage-backend

prepare-environment-evidence-fixtures:
	cd backend && python -m tests.evals.prepare_environment_evidence_fixtures

claude-prompt:
	cd backend && python -m app.services.claude_cli_wrapper --prompt-file "$(PROMPT_FILE)" --model "$(MODEL)"

# Linting
lint:
	cd backend && ruff check .
	cd frontend && npx tsc --noEmit && npx eslint src/

# Database
migrate:
	cd backend && alembic upgrade head

migrate-down:
	cd backend && alembic downgrade -1

seed:
	cd backend && python -m app.seed

# Docker
up:
	docker compose up -d

down:
	docker compose down

reset-db:
	docker compose down db -v
	docker compose up -d db
	@echo "Waiting for Postgres..."
	@sleep 3
	docker compose restart backend
	@echo "DB reset complete. Tables will be recreated on backend startup."

clean:
	docker compose down -v
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf backend/.pytest_cache frontend/dist frontend/node_modules
