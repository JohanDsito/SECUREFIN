# Gestión de supresiones de hallazgos

**Referencias**: constitución, Principio V y Gobernanza; tarea T129.

Las herramientas de análisis (Semgrep, Bandit, pip-audit, npm audit, Trivy) hacen fallar la CI con
severidad alta o crítica. Un hallazgo solo puede suprimirse siguiendo este procedimiento.

## Datos obligatorios de cada supresión

| Campo | Contenido |
|---|---|
| Justificación | Por qué no es un riesgo real (falso positivo) o por qué se acepta temporalmente |
| Alcance | Herramienta, regla o identificador, y ubicación exacta: archivo y línea, o paquete y versión. **Nunca** se desactiva una regla de forma global |
| Responsable | Persona que responde por la supresión |
| Fecha de revisión | Cuándo se revisa o expira |
| Aprobación | Aprobación explícita del revisor en el Pull Request (plantilla `.github/pull_request_template.md`) |

## Tipos

**Falso positivo** (el hallazgo no representa un riesgo):

- Se suprime en el punto exacto con el mecanismo de la herramienta (`# nosemgrep: <regla>`,
  `# nosec <id>`, entrada en el archivo de ignorados de Trivy o pip-audit), con un comentario que
  remite al PR donde se aprobó.

**Riesgo real aceptado temporalmente** (excepción):

- Además de lo anterior, se registra en `plan.md` → Complexity Tracking con riesgo residual,
  control compensatorio, responsable y fecha de revisión o condición de cierre.
- Nunca se aceptan excepciones a las prohibiciones absolutas de la constitución.

## Registro

| Fecha | PR | Herramienta | Regla / ID | Alcance | Tipo | Responsable | Revisión |
|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — |
