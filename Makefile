.DEFAULT_GOAL := help
AEGIS_DATA_DIR ?= data
RUN = uv run --locked --no-sync
CLI = $(RUN) python -m pipelines.cli --data-dir "$(AEGIS_DATA_DIR)"
SELECT = $(if $(SNAPSHOT),--snapshot "$(SNAPSHOT)")

.PHONY: help preflight bootstrap ingest-local validate-data query-local verify-phase1 lint test aws-preflight
help:
	@printf '%s\n' 'G1 targets' '  preflight bootstrap ingest-local validate-data query-local verify-phase1 lint test' 'Set SNAPSHOT=<run-uuid> to pin read and verification targets.'

preflight:
	@sh scripts/preflight.sh

bootstrap:
	uv sync --locked

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

test:
	$(CLI) test $(SELECT)

aws-preflight:
	@printf '%s\n' 'G2 begins with aws-preflight. This target is outside the G1 implementation.' >&2
	@exit 1
