# syntax=docker/dockerfile:1
# Imagen para ejecutar las pruebas del backend en local sin instalar Python ni dependencias en el
# equipo (la usa scripts/dev/run-backend-tests.sh). Misma base que backend/Dockerfile, fijada por
# digest (R17). El código se monta en solo lectura al ejecutar; aquí solo van las dependencias.
ARG PYTHON_IMAGE=python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    COVERAGE_FILE=/tmp/.coverage

# Mismo procedimiento que el CI: dependencias de ejecución con hashes y después las de desarrollo.
COPY backend/requirements.txt backend/requirements-dev.txt /tmp/
RUN pip install --root-user-action=ignore --require-hashes -r /tmp/requirements.txt \
    && pip install --root-user-action=ignore -r /tmp/requirements-dev.txt

RUN useradd --system --create-home tester
USER tester
WORKDIR /app
