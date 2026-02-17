# syntax=docker/dockerfile:1.7

ARG PYTHON_VERSION=3.13.1

FROM python:${PYTHON_VERSION}-slim-bookworm AS preflight
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app

# Keep copy surface explicit for deterministic builds.
COPY scripts ./scripts
COPY tests ./tests
COPY tools ./tools
COPY usnpw ./usnpw
COPY README.md AGENTS.md ./

RUN python tools/release.py preflight

FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    USNPW_API_HOST=0.0.0.0 \
    USNPW_API_PORT=8080 \
    USNPW_API_MAX_CONCURRENT_REQUESTS=256 \
    USNPW_API_SOCKET_TIMEOUT_SECONDS=5 \
    USNPW_API_AUTH_FAIL_LIMIT=16 \
    USNPW_API_AUTH_FAIL_WINDOW_SECONDS=60 \
    USNPW_API_AUTH_BLOCK_SECONDS=300
WORKDIR /app

LABEL org.opencontainers.image.title="UsnPw" \
      org.opencontainers.image.description="Local-first OPSEC username and password generation toolkit"

RUN groupadd --system usnpw \
    && useradd --system --gid usnpw --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin usnpw

# Reduce local post-exploitation surface by stripping setuid/setgid bits in runtime image.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + || true

COPY --from=preflight /app/scripts ./scripts
COPY --from=preflight /app/usnpw ./usnpw

USER usnpw:usnpw

EXPOSE 8080

ENTRYPOINT ["python", "./scripts/usnpw_api.py"]
