FROM public.ecr.aws/awsguru/aws-lambda-adapter:1.1.0@sha256:98d6d1dc9ad3f18c6af7baaa397fb033a57d82f5bffb58ff33bef1c2e1f4f0fe AS adapter
FROM ghcr.io/astral-sh/uv:0.7.19@sha256:2dcbc74e60ed6d842122ed538f5267c80e7cde4ff1b6e66a199b89972496f033 AS uv
FROM public.ecr.aws/lambda/python:3.12@sha256:f229f304f82f5016fe26e4714d05b6a8196e0c6c61b463112841a5e3c3647163 AS dependencies
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv export --quiet --locked --no-default-groups --group backend --no-emit-project --format requirements-txt --output-file /tmp/requirements.txt && \
    uv pip install --no-cache --only-binary :all: --require-hashes --target /build/packages --requirement /tmp/requirements.txt

FROM public.ecr.aws/lambda/python:3.12@sha256:f229f304f82f5016fe26e4714d05b6a8196e0c6c61b463112841a5e3c3647163
WORKDIR /app
COPY --from=adapter /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=dependencies /build/packages ./
COPY backend ./backend
COPY pipelines ./pipelines
COPY schemas ./schemas
COPY sql ./sql
COPY infra/__init__.py infra/settings.py ./infra/
ENV POLARS_MAX_THREADS=2 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    AWS_LWA_INVOKE_MODE=response_stream AWS_LWA_ASYNC_INIT=true AWS_LWA_READINESS_CHECK_PATH=/ready \
    AWS_LWA_READINESS_CHECK_HEALTHY_STATUS=204 AWS_LWA_READINESS_CHECK_TIMEOUT_SECONDS=25
USER 10001
EXPOSE 8080
ENTRYPOINT ["/var/lang/bin/python", "-m", "backend.cloud_api"]
