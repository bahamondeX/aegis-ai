.DEFAULT_GOAL := help
RUN = uv run --locked --no-sync
CLI = $(RUN) python -m pipelines.cli
LAKE = $(RUN) python -m infra.operations
API = $(RUN) python -m backend.cli
AGENT = $(RUN) python -m backend.agentcore
FRONTEND = sh scripts/frontend.sh
SELECT = $(if $(SNAPSHOT),--snapshot "$(SNAPSHOT)")
LATEST_SELECT = $(if $(filter 1,$(LATEST)),--latest)
G2_TARGETS = aws-preflight synth diff diff-local prepare-bootstrap-policy cdk-bootstrap deploy secrets-sync init-tables publish-local ingest-cloud verify-cloud destroy

.PHONY: help preflight bootstrap ingest-local validate-data query-local verify-phase1 lint typecheck test dev smoke-local smoke-investigation smoke-agent-local synth-agent $(G2_TARGETS)
help:
	@printf '%s\n' 'G1 targets' '  preflight bootstrap ingest-local validate-data query-local verify-phase1 lint test' 'G2 targets' '  typecheck $(G2_TARGETS)' 'G3 targets' '  dev smoke-local' 'G4 targets' '  smoke-investigation smoke-agent-local synth-agent' 'Project commands read the root .env. Use SNAPSHOT=<run-uuid> to override its snapshot.' 'Use LATEST=1 with verify-cloud to verify the current cloud release.'

preflight:
	@sh scripts/preflight.sh

bootstrap:
	uv sync --locked --group infra --group backend

ingest-local:
	$(CLI) ingest

validate-data:
	$(CLI) validate $(SELECT)

query-local:
	$(CLI) query $(SELECT)

verify-phase1: lint
	$(CLI) verify $(SELECT)

lint:
	$(RUN) ruff check .
	$(RUN) ruff format --check .

typecheck:
	$(RUN) mypy --follow-imports=skip --ignore-missing-imports --cache-dir "$(or $(AEGIS_DATA_DIR),data)/mypy-cache" pipelines schemas infra backend

test:
	$(CLI) test $(SELECT)

dev:
	$(API) dev $(SELECT) --port "$(or $(PORT),8000)"

smoke-local:
	$(API) smoke $(SELECT)

smoke-investigation:
	$(API) smoke-investigation $(SELECT) $(if $(filter 1,$(BEDROCK)),--bedrock)

smoke-agent-local:
	$(AGENT) --smoke-local $(SELECT)

synth-agent:
	JSII_RUNTIME_PACKAGE_CACHE=disabled $(RUN) python -m infra.agentcore_stack

.PHONY: deploy-agent audit-agent frontend-install lint-ui typecheck-ui build-ui smoke-ui
deploy-agent:
	JSII_RUNTIME_PACKAGE_CACHE=disabled $(RUN) python -m infra.agent_deploy identity
	JSII_RUNTIME_PACKAGE_CACHE=disabled $(RUN) python -m infra.agent_deploy runtime

audit-agent:
	$(RUN) python -m scripts.verify_agent_deployment

frontend-install:
	$(FRONTEND) install --frozen-lockfile

lint-ui:
	$(FRONTEND) lint

typecheck-ui:
	$(FRONTEND) typecheck

build-ui:
	$(FRONTEND) build

smoke-ui:
	$(RUN) python -m scripts.smoke_dashboard

$(G2_TARGETS):
	$(LAKE) $@ $(SELECT) $(LATEST_SELECT)

.PHONY: smoke-ui-extension
smoke-ui-extension:
	$(RUN) python -m scripts.smoke_dashboard --evidence-dir evidence/g5-extension

.PHONY: synth-hosting build-ui-static smoke-ui-static hosting-preflight
hosting-preflight:
	$(RUN) python -m infra.hosting_preflight
synth-hosting:
	JSII_RUNTIME_PACKAGE_CACHE=disabled $(RUN) python -m infra.hosting_stack
build-ui-static:
	$(RUN) python -m scripts.build_static_ui
smoke-ui-static:
	$(RUN) python -m scripts.smoke_static_ui
