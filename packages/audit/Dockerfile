FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 POETRY_VERSION=1.8.4 POETRY_NO_INTERACTION=1 POETRY_VIRTUALENVS_CREATE=true POETRY_VIRTUALENVS_IN_PROJECT=true PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple PIP_TRUSTED_HOST=pypi.tuna.tsinghua.edu.cn

RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpq-dev libffi-dev && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn "poetry==${POETRY_VERSION}"

WORKDIR /app
COPY pyproject.toml poetry.lock* ./
RUN poetry install --only main --no-root --no-directory
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./
# Re-run with --sync to ensure the root package (and console scripts) are installed
RUN poetry install --only main --sync

FROM python:3.12-slim-bookworm AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 libffi8 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r nonroot && useradd -r -g nonroot -u 65532 -m -d /home/nonroot nonroot
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src
COPY --from=builder /app/migrations /app/migrations
COPY --from=builder /app/alembic.ini /app/alembic.ini

ENV PATH="/app/.venv/bin:$PATH" PYTHONPATH="/app/src" PYTHONUNBUFFERED=1

USER nonroot
EXPOSE 8013
ENTRYPOINT ["/app/.venv/bin/python", "-m", "uvicorn"]
CMD ["foundation_audit.main:app", "--host", "0.0.0.0", "--port", "8013", "--no-access-log"]
