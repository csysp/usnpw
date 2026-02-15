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
    USNPW_API_PORT=8080
WORKDIR /app

LABEL org.opencontainers.image.title="UsnPw" \
      org.opencontainers.image.description="Local-first OPSEC username and password generation toolkit" \
      org.opencontainers.image.source="https://github.com/csysp/UsnPw"

RUN groupadd --system usnpw \
    && useradd --system --gid usnpw --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin usnpw

COPY --from=preflight /app/scripts ./scripts
COPY --from=preflight /app/usnpw ./usnpw

USER usnpw:usnpw

EXPOSE 8080

ENTRYPOINT ["python", "./scripts/usnpw_api.py"]
