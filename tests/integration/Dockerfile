FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir \
    pytest==8.3.0 \
    pytest-asyncio==0.24.0 \
    pytest-timeout==2.3.1 \
    httpx==0.27.0 \
    hvac==2.3.0

WORKDIR /app
CMD ["pytest", "/app/tests", "-v", "--tb=short"]
