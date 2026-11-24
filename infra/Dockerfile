FROM ghcr.io/astral-sh/uv:0.7.19@sha256:2dcbc74e60ed6d842122ed538f5267c80e7cde4ff1b6e66a199b89972496f033 AS uv
FROM public.ecr.aws/lambda/python:3.12@sha256:f229f304f82f5016fe26e4714d05b6a8196e0c6c61b463112841a5e3c3647163 AS dependencies
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv export --quiet --locked --no-default-groups --no-emit-project --format requirements-txt --output-file /tmp/requirements.txt && \
    uv pip install --no-cache --only-binary :all: --require-hashes --target /build/packages --requirement /tmp/requirements.txt
RUN PYTHONPATH=/build/packages /var/lang/bin/python - <<'PY'
import duckdb

db = duckdb.connect(config={"extension_directory": "/build/duckdb-extensions"})
db.execute("INSTALL icu FROM core")
# Loading verifies the signature and that the build matches DuckDB and ARM64.
db.execute("LOAD icu")
PY

FROM public.ecr.aws/lambda/python:3.12@sha256:f229f304f82f5016fe26e4714d05b6a8196e0c6c61b463112841a5e3c3647163
COPY --from=dependencies /build/packages ${LAMBDA_TASK_ROOT}
COPY --from=dependencies /build/duckdb-extensions /opt/duckdb/extensions
COPY pipelines ${LAMBDA_TASK_ROOT}/pipelines
COPY schemas ${LAMBDA_TASK_ROOT}/schemas
COPY sql ${LAMBDA_TASK_ROOT}/sql
COPY infra/__init__.py infra/settings.py ${LAMBDA_TASK_ROOT}/infra/
ENV POLARS_MAX_THREADS=2
ENV AEGIS_DUCKDB_EXTENSION_DIR=/opt/duckdb/extensions
CMD ["pipelines.cloud.handler"]
