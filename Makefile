.DEFAULT_GOAL := help
SHELL := /bin/bash
PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
export PYTHONPATH := libs/signalforge:apps/api:.

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ------------------------------------------------------------------ setup ----
.PHONY: install
install: ## Create the venv and install the library with dev extras
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e "libs/signalforge[dev,stream,worker]" \
		"fastapi>=0.115" "uvicorn[standard]" python-multipart
	@echo "done - activate with: source $(BIN)/activate"

.PHONY: install-dashboard
install-dashboard: ## Install the dashboard's node dependencies
	cd apps/dashboard && npm install

# ------------------------------------------------------------------ checks ---
.PHONY: test
test: ## Run the whole Python test suite
	$(BIN)/pytest

.PHONY: test-detections
test-detections: ## Run only the detection rule tests
	$(BIN)/pytest tests/detections -q

.PHONY: test-unit
test-unit: ## Run unit tests
	$(BIN)/pytest tests/unit -q

.PHONY: test-integration
test-integration: ## Run integration tests
	$(BIN)/pytest tests/integration -q

.PHONY: test-e2e
test-e2e: ## Run API end-to-end tests
	$(BIN)/pytest tests/e2e -q

.PHONY: load
load: ## Run the load harness
	SIGNALFORGE_RUN_LOAD=1 $(BIN)/pytest tests/load -s

.PHONY: benchmark
benchmark: ## Benchmark and write benchmarks/latest.json
	$(BIN)/python scripts/benchmark.py --rate 5000 --duration 20 \
		--report benchmarks/latest.json

.PHONY: lint-rules
lint-rules: ## Lint the detection rules (the CI gate)
	$(BIN)/python scripts/validate_rules.py detections

.PHONY: migrate
migrate: ## Apply database migrations (alembic upgrade head)
	$(BIN)/alembic upgrade head

.PHONY: migration
migration: ## Generate a revision from model changes: make migration m="add x"
	@test -n "$(m)" || (echo 'usage: make migration m="what changed"'; exit 1)
	$(BIN)/alembic revision --autogenerate -m "$(m)"
	@echo
	@echo "Review the generated file before committing. Two things to check:"
	@echo "  * a JSONB column renders as astext_type=sa.Text(), not Text()"
	@echo "  * new NOT NULL columns need a server_default to back-fill rows"

.PHONY: migration-status
migration-status: ## Show the current revision and any un-migrated model changes
	$(BIN)/alembic current
	$(BIN)/alembic check

.PHONY: lint
lint: ## Ruff + mypy
	$(BIN)/ruff check libs services apps/api tests scripts
	$(BIN)/mypy libs/signalforge/signalforge apps/api/app || true

.PHONY: format
format: ## Apply ruff formatting
	$(BIN)/ruff format libs services apps/api tests scripts
	$(BIN)/ruff check --fix libs services apps/api tests scripts

.PHONY: check
check: lint lint-rules test ## Everything CI runs

# ------------------------------------------------------------------- run -----
.PHONY: api
api: ## Run the API with reload on :8000
	$(BIN)/uvicorn app.main:app --app-dir apps/api --reload --port 8000

.PHONY: dashboard
dashboard: ## Run the dashboard on :3000
	cd apps/dashboard && npm run dev

.PHONY: demo
demo: ## Walk the account-compromise scenario through the pipeline
	$(BIN)/python scripts/demo.py --scenario account_compromise

.PHONY: seed
seed: ## Push lab telemetry into a running API
	curl -s -X POST http://localhost:8000/api/v1/auth/login \
		-H 'content-type: application/json' \
		-d '{"email":"admin@signalforge.local","password":"signalforge","tenant":"acme"}' \
		| $(PY) -c 'import json,sys;print(json.load(sys.stdin)["access_token"])' > .token
	curl -s -X POST http://localhost:8000/api/v1/lab/simulate \
		-H "authorization: Bearer $$(cat .token)" \
		-H 'content-type: application/json' \
		-d '{"normal_events":400}' | $(PY) -m json.tool

# ------------------------------------------------------------------ docker ---
.PHONY: up
up: ## Start the full stack
	docker compose up -d --build

.PHONY: up-observability
up-observability: ## Start the stack plus Prometheus/Grafana/OpenSearch Dashboards
	docker compose --profile observability up -d --build

.PHONY: down
down: ## Stop the stack
	docker compose down

.PHONY: logs
logs: ## Follow the service logs
	docker compose logs -f api normalizer detector correlator

.PHONY: clean
clean: ## Remove caches, local state and build output
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage coverage.xml
	rm -rf var signalforge.db benchmark.db .token
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
