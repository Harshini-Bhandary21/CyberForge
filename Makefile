.DEFAULT_GOAL := help
BACKEND  := backend
FRONTEND := frontend
PY       := $(BACKEND)/.venv/bin

.PHONY: doctor help install install-api install-web api web dev test lint fmt build demo redteam docker clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n",$$1,$$2}'

install: install-api install-web ## Install backend + frontend dependencies

install-api: ## Create the venv and install the API (with dev tools)
	cd $(BACKEND) && python3 -m venv .venv && .venv/bin/pip install -q -e ".[dev]"

install-web: ## Install frontend dependencies
	cd $(FRONTEND) && npm install

api: ## Run the API on :8000 (auto-reload)
	cd $(BACKEND) && .venv/bin/agentshield serve --reload

web: ## Run the dashboard on :5173
	cd $(FRONTEND) && npm run dev

dev: ## Run API + dashboard together
	$(MAKE) -j2 api web

test: ## Backend tests + frontend typecheck
	cd $(BACKEND) && .venv/bin/pytest
	cd $(FRONTEND) && npm run typecheck

lint: ## Ruff lint + format check
	cd $(BACKEND) && .venv/bin/ruff check src tests && .venv/bin/ruff format --check src tests

fmt: ## Auto-format the backend
	cd $(BACKEND) && .venv/bin/ruff check --fix src tests && .venv/bin/ruff format src tests

build: ## Production build of the dashboard
	cd $(FRONTEND) && npm run build

doctor: ## Check DB, auth and LLM provider configuration (add ARGS=--live for real provider calls)
	cd $(BACKEND) && .venv/bin/agentshield doctor $(ARGS)

demo: ## Print the scripted end-to-end scenario (in-memory, offline)
	cd $(BACKEND) && AGENTSHIELD_DB_PATH=:memory: AGENTSHIELD_USE_LLM=false .venv/bin/agentshield demo

redteam: ## Run a red-team campaign from the CLI
	cd $(BACKEND) && AGENTSHIELD_USE_LLM=false .venv/bin/agentshield redteam --cases 600

deploy/htpasswd:
	@mkdir -p deploy && pw=$$(openssl rand -base64 12) && \
	  echo "admin:$$(openssl passwd -apr1 "$$pw")" > deploy/htpasswd && \
	  echo "Dashboard login created: admin / $$pw  (stored hashed in deploy/htpasswd)"

docker: deploy/htpasswd ## Build and run everything (Postgres + API + dashboard) with Docker Compose
	@test -f .env || { echo "Create .env first: cp .env.example .env (set POSTGRES_PASSWORD)"; exit 1; }
	docker compose up --build

clean: ## Remove build artefacts and local data
	rm -rf $(FRONTEND)/dist $(BACKEND)/data $(BACKEND)/.pytest_cache $(BACKEND)/.ruff_cache
