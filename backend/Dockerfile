# syntax=docker/dockerfile:1
# Imagen del backend (T007). Imagen base fijada por etiqueta y digest (R17; índice multiarquitectura).
ARG PYTHON_IMAGE=python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

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
# Sin socket de control: no se usa y gunicorn 26 intentaría crearlo en /app (sin permiso de escritura).
CMD ["gunicorn", "config.wsgi", "--bind", "0.0.0.0:8000", "--no-control-socket", "--workers", "4", "--threads", "1", "--access-logfile", "-", "--access-logformat", "%(h)s \"%(m)s %(U)s\" %(s)s %(L)s"]
