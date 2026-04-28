# syntax=docker/dockerfile:1.7
#
# Backend API image. Hosts the FastAPI app only — the openfirebase CLI is
# *not* installed here, and neither is the JRE. The scanner worker runs in
# its own image (app/scanner/Dockerfile) and is the only component that
# parses attacker-controlled bundles.

# ---------- builder ----------
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/venv/bin:$PATH

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv

COPY app/backend/pyproject.toml /tmp/web/pyproject.toml
COPY app/backend/src/ /tmp/web/src/
RUN pip install --upgrade pip \
 && pip install '/tmp/web[web]'

# ---------- runtime ----------
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/opt/venv/bin:$PATH

RUN useradd --system --uid 10001 --home-dir /nonexistent \
            --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
# Alembic migrations are run at container startup. alembic.ini references
# paths relative to this directory.
COPY app/backend/alembic/ ./alembic/
COPY app/backend/alembic.ini ./alembic.ini

USER 10001:10001
EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && exec uvicorn openfirebase_web.main:app --host 0.0.0.0 --port 8000"]
