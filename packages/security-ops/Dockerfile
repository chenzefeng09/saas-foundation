FROM python:3.12-slim-bookworm AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 POETRY_VERSION=1.8.4 POETRY_NO_INTERACTION=1 POETRY_VIRTUALENVS_CREATE=true POETRY_VIRTUALENVS_IN_PROJECT=true
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpq-dev libffi-dev && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir "poetry==${POETRY_VERSION}"

# Build context is monorepo `packages/` dir; copy path-dep packages first.
COPY storage /storage
COPY lifecycle /lifecycle
COPY feature-flag /feature-flag

WORKDIR /app
# README.md: pyproject declares it, so installing the project below needs it.
COPY security-ops/pyproject.toml security-ops/poetry.lock* security-ops/README.md ./
RUN poetry install --only main --no-root --no-directory
COPY security-ops/src ./src
RUN poetry install --only main --sync

FROM gcr.io/distroless/python3-debian12:nonroot
WORKDIR /app
# distroless:nonroot now ships Python 3.11 at /usr/bin; the venv built in the
# 3.12 builder symlinks python -> /usr/local/bin/python3.12, so bring that
# interpreter over to keep the venv's interpreter resolvable.
COPY --from=builder /usr/local /usr/local
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src
COPY --from=builder /storage /storage
COPY --from=builder /lifecycle /lifecycle
COPY --from=builder /feature-flag /feature-flag
ENV PATH="/app/.venv/bin:$PATH" PYTHONPATH="/app/src" PYTHONUNBUFFERED=1
USER nonroot
EXPOSE 8019
ENTRYPOINT ["/app/.venv/bin/python", "-m", "uvicorn"]
CMD ["foundation_security_ops.main:app", "--host", "0.0.0.0", "--port", "8019", "--no-access-log"]
