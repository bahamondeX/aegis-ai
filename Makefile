.DEFAULT_GOAL := help
RUN = uv run --locked --no-sync
CLI = $(RUN) python -m pipelines.cli
LAKE = $(RUN) python -m infra.operations
API = $(RUN) python -m backend.cli
SELECT = $(if $(SNAPSHOT),--snapshot "$(SNAPSHOT)")
LATEST_SELECT = $(if $(filter 1,$(LATEST)),--latest)
G2_TARGETS = aws-preflight synth diff diff-local prepare-bootstrap-policy cdk-bootstrap deploy secrets-sync init-tables publish-local ingest-cloud verify-cloud destroy

.PHONY: help preflight bootstrap ingest-local validate-data query-local verify-phase1 lint typecheck test dev smoke-local $(G2_TARGETS)
help:
	@printf '%s\n' 'G1 targets' '  preflight bootstrap ingest-local validate-data query-local verify-phase1 lint test' 'G2 targets' '  typecheck $(G2_TARGETS)' 'G3 targets' '  dev smoke-local' 'Project commands read the root .env. Use SNAPSHOT=<run-uuid> to override its snapshot.' 'Use LATEST=1 with verify-cloud to verify the current cloud release.'

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

$(G2_TARGETS):
	$(LAKE) $@ $(SELECT) $(LATEST_SELECT)
