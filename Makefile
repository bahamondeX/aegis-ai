.DEFAULT_GOAL := help
AEGIS_DATA_DIR ?= data
RUN = uv run --locked --no-sync
CLI = $(RUN) python -m pipelines.cli --data-dir "$(AEGIS_DATA_DIR)"
LAKE = $(RUN) python -m infra.operations --data-dir "$(AEGIS_DATA_DIR)"
SELECT = $(if $(SNAPSHOT),--snapshot "$(SNAPSHOT)")
G2_TARGETS = aws-preflight synth diff diff-local cdk-bootstrap deploy secrets-sync init-tables publish-local ingest-cloud verify-cloud destroy

.PHONY: help preflight bootstrap ingest-local validate-data query-local verify-phase1 lint typecheck test $(G2_TARGETS)
help:
	@printf '%s\n' 'G1 targets' '  preflight bootstrap ingest-local validate-data query-local verify-phase1 lint test' 'G2 targets' '  typecheck $(G2_TARGETS)' 'Set SNAPSHOT=<run-uuid> to pin read, publish, and verification targets.'

preflight:
	@sh scripts/preflight.sh

bootstrap:
	uv sync --locked --group infra

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
	$(RUN) mypy --follow-imports=skip --ignore-missing-imports --cache-dir "$(AEGIS_DATA_DIR)/mypy-cache" pipelines schemas infra

test:
	$(CLI) test $(SELECT)

$(G2_TARGETS):
	$(LAKE) $@ $(SELECT)
