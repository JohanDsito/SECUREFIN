# syntax=docker/dockerfile:1
# Imagen del backend (T007). Fijar el digest al construir por primera vez:
#   docker buildx imagetools inspect python:3.13-slim  ->  python:3.13-slim@sha256:<digest>
ARG PYTHON_IMAGE=python:3.13-slim

FROM ${PYTHON_IMAGE} AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system app && useradd --system --gid app --home-dir /app --shell /usr/sbin/nologin app
WORKDIR /app

# Dependencias bloqueadas con hashes (R17)
COPY requirements.txt .
RUN pip install --require-hashes --no-deps -r requirements.txt

COPY --chown=app:app . .
USER app

EXPOSE 8000
ENV DJANGO_SETTINGS_MODULE=config.settings.lab
CMD ["gunicorn", "config.wsgi", "--bind", "0.0.0.0:8000", "--workers", "4", "--threads", "1", "--access-logfile", "-", "--access-logformat", "%(h)s \"%(m)s %(U)s\" %(s)s %(L)s"]
