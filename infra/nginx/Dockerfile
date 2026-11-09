# syntax=docker/dockerfile:1
# Nginx con el SPA compilado (T008). Contexto de construcción: raíz del repositorio.
# Fijar los digests al construir por primera vez (R17).
ARG NODE_IMAGE=node:22-alpine
ARG NGINX_IMAGE=nginx:1.28-alpine

FROM ${NODE_IMAGE} AS build
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
# Vite es dependencia de desarrollo y hace falta para compilar; nada de node_modules llega a la imagen final
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

FROM ${NGINX_IMAGE}
RUN rm -f /etc/nginx/conf.d/default.conf
COPY infra/nginx/nginx.conf /etc/nginx/nginx.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 443 80 8025
