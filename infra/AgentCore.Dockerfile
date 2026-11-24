FROM ghcr.io/astral-sh/uv:0.7.19@sha256:2dcbc74e60ed6d842122ed538f5267c80e7cde4ff1b6e66a199b89972496f033 AS uv
FROM public.ecr.aws/lambda/python:3.12@sha256:f229f304f82f5016fe26e4714d05b6a8196e0c6c61b463112841a5e3c3647163 AS dependencies
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv export --quiet --locked --no-default-groups --group backend --no-emit-project --format requirements-txt --output-file /tmp/requirements.txt && \
    uv pip install --no-cache --only-binary :all: --require-hashes --target /build/packages --requirement /tmp/requirements.txt

FROM public.ecr.aws/lambda/python:3.12@sha256:f229f304f82f5016fe26e4714d05b6a8196e0c6c61b463112841a5e3c3647163
WORKDIR /app
COPY --from=dependencies /build/packages ./
COPY backend ./backend
COPY pipelines ./pipelines
COPY schemas ./schemas
COPY sql ./sql
COPY infra/__init__.py infra/settings.py ./infra/
ENV POLARS_MAX_THREADS=2 PYTHONDONTWRITEBYTECODE=1
USER 10001
EXPOSE 8080
ENTRYPOINT ["/var/lang/bin/python", "-m", "backend.agentcore"]
