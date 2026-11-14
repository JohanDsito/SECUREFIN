# SecureFin Gateway — contexto para Claude Code

Este archivo es la **fuente de verdad entre equipos y sesiones**: Claude Code lo carga al empezar.
Al terminar una sesión con avances, actualiza la sección "Estado" (con permiso del usuario para el commit).

## Proyecto

Fintech de laboratorio (saldos y operaciones 100 % ficticios) que es el **proyecto final de dos materias**:

- **Ciberseguridad** (prioridad): cada tema del semestre debe verse funcionando y demostrarse en vivo
  al profesor. Matriz tema → control → código → evidencia en `docs/security/README.md`; guion de la
  demo en `docs/security/DEMO-EN-VIVO.md` y `docs/security/demo/demo.sh`; evidencias en
  `docs/security/evidence/`.
- **Ingeniería Web**: se trabaja con **Spec Kit** (spec → plan → tasks → implement). Features en
  `specs/001-iam-access-control` (IAM) y `specs/002-financial-simulation` (finanzas). Las skills
  `speckit-*` están en `.claude/skills`.

Stack: Django 5.2 + DRF (`backend/apps/{core,iam,audit,finance}`), React 19 + Vite (`frontend/`),
PostgreSQL 17, Nginx 1.30, Mailpit; todo con Docker Compose (`infra/compose.yaml`).

## Reglas de trabajo con el usuario (obligatorias)

- Responder en **español**. Trabajar por etapas y entregar un informe al final de cada una.
- **Nunca commit ni push sin autorización explícita.** El push lo suele hacer el usuario.
- `git add` **archivo por archivo** (nunca `git add .` ni `-A`). Antes de cada commit: `git status`,
  revisar el diff y encadenar `git diff --cached --check` con el commit (`if …; then git commit; fi`).
- **Sin coautoría ni firmas de IA** en commits, PRs o comentarios de GitHub (nada de `Co-Authored-By`).
- Nunca `git reset`, `git clean`, `git stash`, `docker compose down -v`, `prune` ni borrar volúmenes.
- No modificar `secrets/`, certificados ni claves. `infra/compose.yaml` y `infra/nginx/nginx.conf` solo
  con permiso explícito. No ejecutar `DELETE`/`TRUNCATE`/`DROP` contra la base del laboratorio: verificar
  privilegios con `has_table_privilege` (solo lectura).
- No marcar tareas en `tasks.md` sin evidencia (pruebas pasando). No inventar endpoints ni requisitos.
- Código de terceros (skills, repos): clonar en una carpeta aislada y revisar antes de instalar.

## Estado (2026-11-13)

- Rama de trabajo `001-iam-access-control` (sincronizada con GitHub). `main` aún sin merge ni etiqueta.
- Hecho: US1–US5 de IAM (incluye limitación por IP y retrasos progresivos por cuenta), la app
  `finance` (spec 002), centro de seguridad, hardening de Nginx (rate limit 429, sin root, Nginx 1.30),
  evidencias E1–E9. Backend: **740 pruebas** en verde, cobertura ~94 %. Semgrep y Bandit limpios.
- Pendiente:
  - **Rediseño visual completo** (ver abajo) — prioridad hasta la entrega.
  - US6 (consulta de auditoría para el Auditor), US7 (recuperación de contraseña) y Polish (T117…).
  - T135/T139: E2E real con Mailpit sin ejecutar (necesita el stack y la contraseña de Mailpit).
  - T140 (recuperar al primer admin antes de producción) y T141 (break-glass encola password_reset
    cuando exista el handler de US7).
  - Imagen del backend: 47 CVE de Debian sin parche (Trivy en el CI seguirá en rojo hasta decidir
    `--ignore-unfixed` o una imagen base mínima).

## Rediseño visual (decidido el 2026-11-13; el usuario aceptó todas las recomendaciones)

- **Fecha límite**: el usuario dijo "martes 16", pero el 16-11-2026 es **lunes**. Confirmar al empezar.
- **Estilo**: fintech moderna y cercana (tipo Nubank/Revolut) con toques de panel de ciberseguridad.
  Modo **claro y oscuro** (según el sistema), claro por defecto. Se mantiene el nombre "SecureFin
  Gateway" con un logotipo tipográfico simple. Debe funcionar bien en móvil.
- **Fases** (commit por fase con autorización): 1) portada, login, MFA y panel del cliente;
  2) finanzas; 3) administración, auditoría y centro de seguridad.
- **Proceso**: diagnóstico con `impeccable` → tres propuestas visuales como prototipos HTML para que
  elija → `DESIGN.md` validado → aplicar por fases al SPA con pruebas en cada fase.
- **Solo visual**: no tocar backend ni comportamiento. Punto de partida: `frontend/src/styles.css`,
  `frontend/src/components/Header.jsx`, `frontend/src/pages/SecurityCenter.jsx`.
- **Restricciones de la CSP** (`style-src 'self'`, sin `font-src` externo): fuentes **locales** dentro
  del proyecto (nada de Google Fonts ni CDNs), sin `<style>` ni estilos en línea, sin `localStorage` ni
  `sessionStorage` (regla Semgrep). Conservar los `id` y etiquetas que usan las E2E
  (`frontend/tests/e2e/*.spec.js`). Formularios compatibles con gestores de contraseñas.
- `impeccable` escribirá `PRODUCT.md`, `DESIGN.md` y `.impeccable/`: commitear los `.md` y decidir qué
  parte de `.impeccable/` va a `.gitignore`.

## Skills de diseño (instalar con `scripts/setup/install-claude-skills.ps1`)

Fijadas a los commits auditados el 2026-11-13:

| Skill | Uso en SecureFin | Notas de seguridad |
|---|---|---|
| `impeccable` | Guía principal: diagnóstico, `DESIGN.md`, pulido | Descarga y ejecuta su motor nativo (`impeccable.exe`, verificado por SHA-256) en el primer uso: **autorizado**. Hooks solo con `/impeccable hooks on` y permiso |
| `ui-ux-pro-max` | Paletas, tipografías, guías UX | `python -I ~/.claude/skills/ui-ux-pro-max/scripts/search.py "<consulta>" --design-system` |
| `design-taste-frontend` | Portada pública | Lanza Chrome sin interfaz con perfil temporal; descarga fotos de stock |
| `huashu-design` | Prototipos HTML de las propuestas | En chino. Scripts de nube (ByteDance) solo con `--yes`: no usarlos. Su memoria guarda citas del usuario |
| Emil Kowalski (19, p. ej. `emil-design-eng`, `animate`, `break-ui`) | Pulido, animación, datos extremos | Solo Markdown |

Las plantillas de estas skills cargan Google Fonts/CDNs: **no copiarlas tal cual** al SPA.

## Cómo trabajar (Windows + Git Bash)

- Preparar un equipo nuevo: `docs/SETUP-NUEVO-EQUIPO.md`.
- Secretos y stack: `bash scripts/setup.sh` (genera secretos si faltan y muestra la contraseña de
  Mailpit una sola vez; luego base de datos → migraciones → resto). Abrir **https://securefin.local**
  (la API rechaza `127.0.0.1` con 400 por `ALLOWED_HOSTS`).
- Pruebas del backend: `bash scripts/dev/run-backend-tests.sh` (o con argumentos de pytest).
- E2E sin backend: `cd frontend && npm run build && npx vite preview --port 4173`, y en otra terminal
  `SECUREFIN_STACK_URL=http://localhost:4173 npx playwright test --grep-invert "token real"`.
  `vite preview` escucha en `localhost` (no `127.0.0.1`), y al parar la tarea el proceso `node` puede
  quedarse vivo: comprobar el puerto 4173 antes de repetir.
- SAST como en el CI: `docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep:latest semgrep scan --error
  --metrics=off --config p/django --config p/python --config p/react --config p/secrets --config .semgrep/`
  y Bandit con la imagen de pruebas: `python -m bandit -r backend/apps backend/config -ll`.
- Migraciones: `makemigrations --check` debe decir "No changes detected".
- Peculiaridades: en Git Bash, `docker` necesita `MSYS_NO_PATHCONV=1`, pero `curl`/`openssl` no.
  `curl` de Git Bash usa Schannel: `--ssl-no-revoke`. `tshark` en loopback: sin filtro de captura `-f`.
  `nmap` y `ab` se usan por Docker (`instrumentisto/nmap:7.95`, `httpd:2.4-alpine`), lanzando `ab`
  desde la red `securefin_edge_net`. Las pruebas transaccionales usan el fixture `concurrent_db`.
