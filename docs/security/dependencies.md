# Dependencias, versiones y bloqueo

**Referencias**: research R17; tarea T126; constitución, Principios V y VIII.

## Versiones fijadas (2026-11-09)

| Componente | Versión | Estado |
|---|---|---|
| Python (imagen) | 3.13 (`python:3.13-slim`); pruebas locales con 3.12 | Django 5.2 admite Python 3.10–3.13 |
| Django | **5.2.19** (LTS) | Última 5.2.x disponible al bloquear; soporte hasta abril de 2028 |
| Django REST Framework | **3.18.3** | Ver la decisión de abajo |
| argon2-cffi, cryptography, pyotp, segno, psycopg 3, gunicorn | Ver `backend/requirements.txt` | Bloqueadas con hashes |
| React / react-router / Vite / @playwright/test | 19.3.1 / 7.18.5 / 7.3.7 / 1.65.0 | `frontend/package-lock.json`; Playwright solo en desarrollo |

## Decisión DRF (T126)

El plan proponía DRF 3.16.x como "base segura" y la 3.18.1 condicionada. Al ejecutar `pip-audit`
durante la implementación, **DRF 3.16.1 resultó tener cinco vulnerabilidades conocidas**:

| ID | Resumen | Corregida en |
|---|---|---|
| CVE-2026-114136 | Un atacante no autenticado salta `DATA_UPLOAD_MAX_MEMORY_SIZE` y fuerza asignación de memoria arbitraria | 3.18.2 |
| CVE-2026-114138 | Coste cuadrático al analizar la cabecera `Accept` (DoS) | 3.18.2 |
| CVE-2026-114137 | Borrar un token mediante `TokenProxy` no lo elimina (no aplica: no usamos tokens de DRF) | 3.18.2 |
| PYSEC-2026-3827 | `request.data` salta `DATA_UPLOAD_MAX_MEMORY_SIZE` | 3.17.2 |
| PYSEC-2026-3828 | `AdminRenderer` puede revelar datos protegidos (no aplica: no usamos `AdminRenderer`) | 3.17.2 |

Las dos primeras afectan directamente a esta API, que analiza JSON en endpoints anónimos (Nginx
limita el cuerpo a 16 KiB, pero no protege del vector de la cabecera `Accept`). Se aplicaron los
criterios de R17:

| Criterio | Resultado |
|---|---|
| Versión publicada | 3.18.1, 3.18.2 y 3.18.3 están publicadas; se fija la última, **3.18.3** |
| Compatible con Django 5.2 y Python 3.13 | La 3.18 retiró Django 4.2, 5.0 y 5.1; Django 5.2 sigue soportado |
| `pip-compile` sin conflictos | Resuelto con hashes |
| Suite completa en verde | 158 pruebas, incluidas TS-C y TS-SC |
| Cambio incompatible (errores de `ListSerializer`) | Sin impacto: el contrato no usa `many=True` |

`pip-audit --strict`: **sin vulnerabilidades conocidas** tras la actualización.

## Estrategia de bloqueo

| Ecosistema | Estrategia |
|---|---|
| Python | `requirements.in` → `pip-compile --generate-hashes` → `requirements.txt`; instalación con `--require-hashes --no-deps` |
| Node | `package-lock.json` versionado e instalación con `npm ci` |
| Contenedores | Las imágenes base deben fijarse por *digest* (`imagen:tag@sha256:…`) al construir por primera vez. **Pendiente**: hoy `infra/compose.yaml` y los Dockerfiles usan etiquetas; ver los riesgos residuales del informe de implementación |
| Actualizaciones | Nunca sin comprobar la compatibilidad; la suite de conformidad de sesión (TS-SC) es obligatoria antes de actualizar Django |
