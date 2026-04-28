# syntax=docker/dockerfile:1.7
#
# Scanner worker image. This is the *only* container that runs the
# openfirebase CLI (and therefore parses attacker-controlled APK/IPA
# bundles via androguard + apksigner). Deliberately minimal:
#
#   * no FastAPI, uvicorn, fastapi-users, python-multipart — the web
#     surface lives in the backend image only. We install the
#     shared package without its ``[web]`` extras so those never land here.
#   * apksigner.jar is pre-downloaded at build time so the runtime
#     filesystem can stay read-only (runtime has no network path to
#     Google's build-tools download either).
#   * non-root user, no shell, no HOME.

# ---------- builder ----------
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/venv/bin:$PATH

# build-essential is only needed while compiling native wheels
# (androguard pulls in cryptography / lxml).
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential git \
 && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv

# Install openfirebase itself.
COPY openfirebase/ /tmp/openfirebase/openfirebase/
COPY pyproject.toml README.md LICENSE* /tmp/openfirebase/
RUN pip install --upgrade pip \
 && pip install /tmp/openfirebase

# Install the web-backend package core only (no [web] extra) — we need
# the shared models / runner / ingest / storage / worker modules.
COPY app/backend/pyproject.toml /tmp/web/pyproject.toml
COPY app/backend/src/ /tmp/web/src/
RUN pip install /tmp/web

# Pre-download apksigner.jar into the openfirebase package's tools/
# directory so the read-only runtime doesn't need network or write access
# to site-packages just to do signature extraction.
RUN python -c "from openfirebase.extractors.signature_extractor import SignatureExtractor; \
               p = SignatureExtractor.setup_apksigner(); \
               assert p and p.is_file(), 'apksigner.jar prefetch failed'"

# ---------- runtime ----------
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/opt/venv/bin:$PATH \
    HOME=/tmp

# JRE for apksigner. Nothing else.
RUN apt-get update \
 && apt-get install -y --no-install-recommends default-jre-headless \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /tmp \
            --shell /usr/sbin/nologin scanner

COPY --from=builder /opt/venv /opt/venv

USER 10001:10001
WORKDIR /tmp

CMD ["python", "-m", "openfirebase_web.worker.main"]
