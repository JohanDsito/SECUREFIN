## Descripción

<!-- Qué cambia y por qué. Enlaza las tareas (TNNN) y los requisitos (FR/SC) afectados. -->

## Verificación

- [ ] Pipeline en verde: `static`, `unit`, `integration` y `stack`.
- [ ] Ninguna prueba omitida por falta de infraestructura.
- [ ] No se introducen secretos, tokens ni credenciales (ni en código, logs, artefactos o capturas).
- [ ] Las operaciones administrativas nuevas registran su evento en la misma transacción.
- [ ] Constitución revisada: ninguna desviación, o desviación registrada en `plan.md` → Complexity Tracking.

## Supresiones de hallazgos (Principio V; `docs/security/suppressions.md`)

- [ ] Este PR **no** suprime ningún hallazgo.
- [ ] Este PR suprime hallazgos y cada uno está descrito abajo, pendiente de aprobación explícita.

| Herramienta | Regla / ID | Alcance (archivo:línea o paquete) | Tipo (falso positivo / riesgo aceptado) | Justificación | Responsable | Fecha de revisión |
|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |

> Un *riesgo aceptado* además debe registrarse en `plan.md` → Complexity Tracking.
> El revisor aprueba cada supresión explícitamente en la revisión del PR.
