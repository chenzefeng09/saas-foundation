# =============================================================================
# foundation-identity Dockerfile (multi-stage, distroless)
# =============================================================================

# ---------- Stage 1: builder ----------
FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.8.4 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=true \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_CACHE_DIR=/tmp/poetry_cache

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      libpq-dev \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir "poetry==${POETRY_VERSION}"

WORKDIR /app

# 先复制依赖描述，最大化 layer cache
COPY pyproject.toml poetry.lock* ./
RUN --mount=type=cache,target=/tmp/poetry_cache \
    poetry install --only main --no-root --no-directory

# 再复制源码
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./

RUN poetry install --only main

# ---------- Stage 2: runtime (distroless) ----------
FROM gcr.io/distroless/python3-debian12:nonroot

WORKDIR /app

# 拷贝运行时所需
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src
COPY --from=builder /app/migrations /app/migrations
COPY --from=builder /app/alembic.ini /app/alembic.ini

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/src" \
    PYTHONUNBUFFERED=1

USER nonroot

EXPOSE 8001

# distroless 没有 shell，CMD 必须是 exec 形式
ENTRYPOINT ["/app/.venv/bin/python", "-m", "uvicorn"]
CMD ["foundation_identity.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8001", \
     "--no-access-log"]
