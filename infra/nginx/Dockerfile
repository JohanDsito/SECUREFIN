# syntax=docker/dockerfile:1
# Nginx con el SPA compilado (T008). Contexto de construcción: raíz del repositorio.
# Imágenes base fijadas por etiqueta y digest (R17; índices multiarquitectura).
ARG NODE_IMAGE=node:22-alpine@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202
# 1.30 = rama estable actual. La imagen oficial 1.28-alpine (nginx 1.28.3) tenía 5 CVE HIGH en el
# propio binario (HTTP/2, rewrite, slice) y no hay imagen oficial 1.28 que las corrija (Trivy, E8).
ARG NGINX_IMAGE=nginx:1.30-alpine@sha256:583b7f2fce1cdb8da5ad5c39ebd3c33b98b87d493190e548bdee1fa8c619c311

FROM ${NODE_IMAGE} AS build
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
# Vite es dependencia de desarrollo y hace falta para compilar; nada de node_modules llega a la imagen final
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

FROM ${NGINX_IMAGE}
# Parches de seguridad de Alpine publicados después del digest fijado (Trivy: 73 CVE HIGH/CRITICAL
# con versión corregida; evidencia E8).
RUN apk upgrade --no-cache
RUN rm -f /etc/nginx/conf.d/default.conf
COPY infra/nginx/nginx.conf /etc/nginx/nginx.conf
COPY --from=build /src/dist /usr/share/nginx/html
# Sin root (Trivy DS-0002): Docker permite a usuarios sin privilegios usar los puertos 80/443 dentro
# del contenedor (net.ipv4.ip_unprivileged_port_start=0). Si alguien compromete Nginx, no es root.
USER nginx
EXPOSE 443 80 8025
