---
description: "Tareas de implementación de la simulación financiera SecureFin"
---

# Tareas: Simulación financiera SecureFin

**Entrada**: documentos de diseño en `specs/002-financial-simulation/`

**Prerequisitos**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/finance-api.md`, `quickstart.md`

**Pruebas**: obligatorias por la constitución del proyecto para controles de autorización, datos financieros, auditoría y consistencia. Escribir primero, demostrar fallo y ejecutar en cada tarea del módulo.

**Organización**: tareas agrupadas por historia para entregar incrementos verificables.

## Formato: `[ID] [P?] [Historia] Descripción`

- `[P]`: puede ejecutarse en paralelo sin dependencias de tareas incompletas.
- `[US#]`: historia de la spec correspondiente.
- Todas las tareas incluyen los archivos concretos a modificar o crear.

## Rutas

- Backend: `backend/apps/finance/`, `backend/config/`, `backend/apps/iam/`, `backend/apps/audit/`
- Backend tests: `backend/tests/{unit,integration,security,contract,acceptance}/`
- Frontend: `frontend/src/{api,components/finance,pages/finance}/`, `frontend/src/App.jsx`
- Infraestructura y evidencia: `infra/postgres/init/`, `specs/002-financial-simulation/`

---

## Fase 1: Setup

**Propósito**: establecer el módulo financiero en el monolito actual.

- [ ] T001 Crear la estructura Python `backend/apps/finance/{api/serializers,api/views,models,policies,services,migrations}` y los `__init__.py` necesarios.
- [ ] T002 Crear `backend/apps/finance/apps.py` con etiqueta única `finance` y registrar `apps.finance` en `backend/config/settings/base.py`.
- [ ] T003 Añadir `path("api/v1/finance/", include("apps.finance.api.urls"))` en `backend/config/urls.py` sin cambiar las rutas IAM existentes.

---

## Fase 2: Fundamentos compartidos

**Propósito**: invariantes contables, auditoría y permisos que bloquean todas las historias.

- [ ] T004 [P] Añadir permisos de finanzas por rol (`finance.accounts.self`, `finance.transfers.create`, `finance.cards.self`, `finance.risk.read`, `finance.approvals.decide`, `finance.limits.manage`) a `backend/apps/iam/policies/matrix.py`; Cliente opera recursos propios, Administrador MFA administra límites/decide y Auditor solo lectura.
- [ ] T005 Crear `backend/apps/finance/models/` para `DemoAccount`, `FinancialTransaction`, `LedgerEntry`, `ApprovalDecision`, `FinancialLimit`, `RiskRule`, `RiskAlert`, `DemoCard` y `FinancialNotification` conforme a `data-model.md`: IDs UUID; monedas `COP|USD`; saldos/montos enteros en unidades menores; saldos no negativos; `description` de máximo 140 caracteres; estados únicamente los enumerados en el modelo; clave idempotente única por creador/ámbito.
- [ ] T006 Añadir `backend/apps/finance/models/__init__.py`, cargar todos los modelos sin importación cíclica y generar la migración inicial bajo `backend/apps/finance/migrations/`.
- [ ] T007 Crear migración PostgreSQL en `backend/apps/finance/migrations/` con trigger que rechace UPDATE/DELETE/TRUNCATE de `LedgerEntry` y REVOKE de esos privilegios a `securefin_app`; permitir INSERT/SELECT de asientos al rol de ejecución.
- [ ] T008 [P] Crear `backend/tests/unit/test_finance_models.py` para restricciones de moneda, montos, estados, idempotencia, relación de propietarios y prohibición de modificar/eliminar asientos.
- [ ] T009 Crear `backend/tests/integration/test_finance_postgres_invariants.py` para ejecutar trigger/privilegios como runtime, confirmar atomicidad de rollback y reconciliar doble partida por moneda en PostgreSQL real.
- [ ] T010 Ampliar el catálogo y allowlist de auditoría en `backend/apps/audit/models.py` y `backend/apps/audit/services.py` para operaciones financieras, aprobaciones, alertas, tarjetas y cambios de límites; prohibir metadatos de PAN/CVV, credenciales, códigos y números completos.
- [ ] T011 Crear `backend/apps/finance/policies/permissions.py` y `backend/apps/finance/services/audit.py` para autorización por función/objeto y eventos financieros dentro de la misma transacción de dominio.
- [ ] T012 Crear `backend/tests/security/test_finance_permissions.py` y `backend/tests/security/test_finance_audit.py` con matriz cliente/admin/auditor, accesos cruzados, MFA requerido y metadata sin datos sensibles.

**Checkpoint**: modelos, permisos y auditoría ejecutables en PostgreSQL; ninguna tarea de historia puede publicar saldos sin doble partida y autorización.

---

## Fase 3: Historia 1 — Panel y cuentas propias (Prioridad: P1, MVP)

**Meta**: cada Cliente ve su panel y su cuenta COP de bienvenida; puede abrir cuentas adicionales vacías.

**Prueba independiente**: crear dos Clientes; cada uno recibe exactamente una cuenta COP con COP 5.000.000 ficticios; abrir una cuenta USD adicional con saldo cero; ninguno consulta la cuenta del otro.

### Pruebas

- [ ] T013 [P] [US1] Crear `backend/tests/acceptance/test_finance_accounts_dashboard.py` para provisión única en registro/activación, panel por moneda, apertura COP/USD cero, duplicados y acceso cruzado.
- [ ] T014 [P] [US1] Crear `backend/tests/contract/test_finance_accounts_contract.py` para `GET /dashboard`, `GET /accounts`, `GET /accounts/{id}` y `POST /accounts`, incluyendo campos extra/rechazados, autenticación, CSRF y status codes.

### Implementación

- [ ] T015 [US1] Implementar `backend/apps/finance/services/accounts.py` para apertura de cuenta propia, enmascarado sintético y provisión idempotente de una cuenta COP con COP 500.000.000 unidades menores, balanceada contra la cuenta interna demo y auditada.
- [ ] T016 [US1] Invocar `ensure_welcome_account(user)` desde el punto de creación de usuarios Cliente en `backend/apps/iam/services/`; impedir reprovisionar fondos al reintentar registro/activación.
- [ ] T017 [P] [US1] Implementar serializers estrictos de cuentas y panel en `backend/apps/finance/api/serializers/accounts.py`; no aceptar owner, saldo, estado ni identificador privado del cliente.
- [ ] T018 [US1] Implementar `backend/apps/finance/services/dashboard.py` con sumas separadas por COP/USD, cuentas del usuario y actividad paginada propia.
- [ ] T019 [US1] Implementar vistas `backend/apps/finance/api/views/accounts.py` con sesión completa, permisos de cliente y respuestas 404 uniformes para cuentas ajenas.
- [ ] T020 [US1] Añadir rutas `backend/apps/finance/api/urls.py` para `/dashboard`, `/accounts` y `/accounts/{account_id}` sin incluir datos de cuentas ajenas.
- [ ] T021 [US1] Añadir `frontend/src/pages/finance/Dashboard.jsx` y `frontend/src/components/finance/AccountCard.jsx` con etiquetas visibles de “saldo de demostración”, moneda y estados.
- [ ] T022 [US1] Añadir `frontend/src/pages/finance/OpenAccount.jsx`, ruta y navegación en `frontend/src/App.jsx`; apertura de cuenta con selección COP/USD y saldo inicial no editable.
- [ ] T023 [US1] Crear `frontend/tests/e2e/finance-dashboard.spec.js` para cargar el panel, verificar cuenta inicial, abrir cuenta USD y comprobar mensajes de error/sin cuentas.

**Checkpoint**: un Cliente puede observar saldos ficticios y abrir cuentas sin cambiar el saldo inicial provisto por servidor.

---

## Fase 4: Historia 3 — Transferencias simuladas (Prioridad: P1)

**Meta**: Cliente prepara y confirma transferencias con estado, políticas, idempotencia y débitos/créditos atómicos.

**Prueba independiente**: transferir entre cuentas activas propias/ajenas compatibles; verificar el saldo, dos asientos y movimientos; errores y repeticiones no producen saldo parcial ni duplicado.

### Pruebas

- [ ] T024 [P] [US3] Crear `backend/tests/integration/test_finance_transfers.py` para vista previa, transferencias COP/USD, asientos balanceados, saldo insuficiente, cuenta cerrada, misma cuenta y mezcla de monedas.
- [ ] T025 [P] [US3] Crear `backend/tests/security/test_finance_transfer_concurrency.py` con transferencias concurrentes sobre la misma cuenta, orden de locks y resultado sin sobregiro.
- [ ] T026 [P] [US3] Crear `backend/tests/contract/test_finance_transfers_contract.py` para serializer estricto, `Idempotency-Key` obligatorio, payload idéntico/reutilizado diferente, CSRF y respuestas de estado.

### Implementación

- [ ] T027 [US3] Crear `backend/apps/finance/services/transfers.py` con validación de propiedad/estado/moneda/monto, previsualización sin efectos y revalidación al confirmar.
- [ ] T028 [US3] Implementar en `backend/apps/finance/services/ledger.py` la operación `transaction.atomic`: bloquear cuentas por UUID ordenado, comprobar saldo/límites bajo lock, actualizar proyección y crear ambos asientos inmutables.
- [ ] T029 [US3] Implementar persistencia y resolución de idempotencia en `backend/apps/finance/services/transfers.py`; mismo key+fingerprint retorna el resultado original y mismo key con fingerprint distinto responde conflicto.
- [ ] T030 [P] [US3] Añadir serializers `backend/apps/finance/api/serializers/transfers.py` con `amount_minor > 0`, máximo de descripción 140, monedas COP/USD y sin campos de estado/saldo/riesgo.
- [ ] T031 [US3] Añadir `backend/apps/finance/api/views/transfers.py` para preview, confirmar y consultar solo transferencias autorizadas; añadir rutas en `backend/apps/finance/api/urls.py`.
- [ ] T032 [US3] Añadir `frontend/src/pages/finance/Transfer.jsx` con selección de cuenta, destino, monto/moneda, vista previa y confirmación explícita; generar y conservar clave idempotente por intento.
- [ ] T033 [US3] Añadir vista de detalle/estado y navegación financiera en `frontend/src/pages/finance/TransferResult.jsx` y `frontend/src/App.jsx`.
- [ ] T034 [US3] Crear `frontend/tests/e2e/finance-transfers.spec.js` para preview, confirmación, persistencia reflejada, rechazo visible e impedir doble envío accidental.

**Checkpoint**: transacciones completadas son de doble partida y el servicio sigue siendo correcto bajo concurrencia y reintentos.

---

## Fase 5: Historia 2 — Historial de movimientos (Prioridad: P2)

**Meta**: Cliente filtra y consulta movimientos persistidos de sus cuentas.

**Prueba independiente**: generar transacciones para dos clientes; cada filtro de fecha, estado, moneda y tipo devuelve únicamente los movimientos del titular.

### Pruebas

- [ ] T035 [P] [US2] Crear `backend/tests/contract/test_finance_transactions_contract.py` para filtros ISO, paginación acotada, filtros inválidos y aislamiento de propietario.
- [ ] T036 [P] [US2] Añadir casos de persistencia, orden y límites de ventana a `backend/tests/acceptance/test_finance_accounts_dashboard.py`.

### Implementación

- [ ] T037 [US2] Implementar `backend/apps/finance/services/transactions.py` para unir asientos y transacciones de cuentas propias, filtrar fechas/tipo/estado/moneda y paginar.
- [ ] T038 [US2] Añadir `backend/apps/finance/api/serializers/transactions.py`, vista y ruta GET `/transactions` con fecha ISO, límite de página y autorización por objeto.
- [ ] T039 [US2] Crear `frontend/src/pages/finance/Activity.jsx` y componente `frontend/src/components/finance/TransactionTable.jsx` con filtros combinables, estados vacíos y cuentas enmascaradas.
- [ ] T040 [US2] Añadir pruebas E2E de filtros y separación de datos en `frontend/tests/e2e/finance-activity.spec.js`.

**Checkpoint**: un movimiento completado puede leerse de nuevo por el titular, pero jamás por otro cliente.

---

## Fase 6: Historia 5 — Aprobaciones, límites y administración (Prioridad: P2)

**Meta**: las operaciones de riesgo esperan decisiones verificadas; Admin configura políticas, Auditor solo consulta.

**Prueba independiente**: evaluar cada umbral COP/USD; aprobar/rechazar como Administrador MFA; validar dos aprobadores distintos y lecturas de Auditor sin capacidad de mutación.

### Pruebas

- [ ] T041 [P] [US5] Crear `backend/tests/acceptance/test_finance_approvals.py` para umbrales inmediatamente bajo/en/sobre COP 1M/5M/10M y USD 250/1250/2500, incluyendo postings y saldos.
- [ ] T042 [P] [US5] Crear `backend/tests/security/test_finance_separation_of_duties.py` para creador no aprueba, duplicación de aprobador, Admin sin MFA y Auditor/Cliente sin acciones write.
- [ ] T043 [P] [US5] Crear `backend/tests/contract/test_finance_admin_contract.py` para limits, approvals, summaries, listas y auditoría de cambios.

### Implementación

- [ ] T044 [US5] Implementar `backend/apps/finance/policies/limits.py` con valores COP 10M/20M/100M y USD 2.5k/5k/25k, umbrales COP 1M/5M/10M y USD 250/1250/2500; sin conversión.
- [ ] T045 [US5] Implementar en `backend/apps/finance/services/approvals.py` los estados terminales, huella de detalles, aprobación única por persona, autor distinto y posting solo tras revalidar saldo/políticas.
- [ ] T046 [US5] Implementar `backend/apps/finance/services/admin.py` para cambios de límites con motivo, precedencia explícita de política y evento append-only en transacción.
- [ ] T047 [P] [US5] Implementar serializers de administración en `backend/apps/finance/api/serializers/admin.py` y `backend/apps/finance/api/serializers/limits.py` con lista permitida y versión esperada.
- [ ] T048 [US5] Implementar `backend/apps/finance/api/views/admin.py` y rutas en `backend/apps/finance/api/urls.py`; permisos Admin MFA para writes y Auditor read-only.
- [ ] T049 [US5] Implementar `frontend/src/pages/finance/admin/Approvals.jsx`, `frontend/src/pages/finance/admin/Limits.jsx` y tabla reutilizable en `frontend/src/components/finance/ApprovalQueue.jsx`.
- [ ] T050 [US5] Añadir rutas por rol y enlaces en `frontend/src/App.jsx`/`frontend/src/pages/finance/Dashboard.jsx`, sin usar el frontend como frontera de autorización.
- [ ] T051 [US5] Crear `frontend/tests/e2e/finance-approvals.spec.js` para aprobación/rechazo, MFA, creador no aprobador, dos aprobadores, límites y rol auditor read-only.

**Checkpoint**: el saldo permanece sin cambios mientras hay aprobación pendiente y solo se publica después del quórum y revalidación.

---

## Fase 7: Historia 6 — Riesgo y alertas (Prioridad: P2)

**Meta**: reglas locales generan nivel, motivo, acción y alertas sin saltarse controles contables.

**Prueba independiente**: disparar cada regla de riesgo configurable y comprobar que el movimiento, paso de aprobación, alerta y auditoría concuerdan.

### Pruebas

- [ ] T052 [P] [US6] Crear `backend/tests/unit/test_finance_risk_rules.py` para ventana/frecuencia, monto inusual, destinatario nuevo, intento de exceso y login sospechoso.
- [ ] T053 [P] [US6] Crear `backend/tests/integration/test_finance_risk_alerts.py` para nivel/acción, eventos y persistencia de alertas.
- [ ] T054 [P] [US6] Añadir casos de permiso y no filtración de metadata a `backend/tests/security/test_finance_permissions.py`.

### Implementación

- [ ] T055 [US6] Implementar `backend/apps/finance/services/risk.py` con reglas deterministas configurables, severidades low/medium/high/critical y acciones; las reglas no sustituyen autorización/saldo/límites.
- [ ] T056 [US6] Integrar evaluación y alertas en `backend/apps/finance/services/transfers.py` dentro del flujo de confirmación y decisión.
- [ ] T057 [US6] Implementar filtros de alertas, resumen agregado, gestión de reglas y permisos de `backend/apps/finance/services/admin.py` y `backend/apps/finance/api/views/admin.py`.
- [ ] T058 [US6] Crear notificaciones in-app no sensibles en `backend/apps/finance/services/notifications.py` para creación, aprobación/rechazo, límites, cambios y actividad sospechosa.
- [ ] T059 [US6] Añadir vistas `frontend/src/pages/finance/admin/RiskOverview.jsx` y `frontend/src/components/finance/AlertList.jsx` con severidad, motivo y estado sin datos completos.
- [ ] T060 [US6] Crear `frontend/tests/e2e/finance-risk.spec.js` para alertas y vistas de solo lectura de auditor/admin.

**Checkpoint**: cada regla activa queda explicada, auditable y ejecuta la acción definida sin alterar el doble control contable.

---

## Fase 8: Historia 4 — Tarjetas virtuales de demostración (Prioridad: P3)

**Meta**: Cliente consulta y congela/descongela una tarjeta ficticia no utilizable como medio de pago.

**Prueba independiente**: Cliente cambia el estado de su tarjeta; una cuenta distinta no logra leerla ni cambiarla; la respuesta y la base no contienen PAN/CVV.

### Pruebas

- [ ] T061 [P] [US4] Crear `backend/tests/acceptance/test_finance_demo_cards.py` para creación/consulta/estado, propiedad, auditoría y ausencia de PAN/CVV.
- [ ] T062 [P] [US4] Crear `backend/tests/contract/test_finance_cards_contract.py` para lista de campos permitidos, CSRF, permisos y respuestas 404 uniformes.

### Implementación

- [ ] T063 [US4] Implementar `backend/apps/finance/services/cards.py` para alta de alias ficticio, lista propia, congelación/descongelación auditada y estados idempotentes.
- [ ] T064 [P] [US4] Implementar `backend/apps/finance/api/serializers/cards.py` y `backend/apps/finance/api/views/cards.py` sin campos PAN/CVV/PIN y con BOLA protection.
- [ ] T065 [US4] Añadir rutas de tarjetas a `backend/apps/finance/api/urls.py`.
- [ ] T066 [US4] Crear `frontend/src/pages/finance/Cards.jsx` y `frontend/src/components/finance/DemoCard.jsx` con advertencia visible “No válida para pagos reales”.
- [ ] T067 [US4] Añadir navegación de tarjetas en `frontend/src/pages/finance/Dashboard.jsx` y `frontend/src/App.jsx`.
- [ ] T068 [US4] Crear `frontend/tests/e2e/finance-cards.spec.js` para consultar, congelar, descongelar y confirmar campos ficticios enmascarados.

**Checkpoint**: las tarjetas son únicamente estado/alias, no incluyen credenciales de pago ni integración externa.

---

## Fase 9: Polish y validación transversal

- [ ] T069 [P] Actualizar `specs/002-financial-simulation/quickstart.md` con comandos exactos y evidencia reproducible para todas las historias.
- [ ] T070 [P] Añadir etiquetas visibles “simulación académica / sin dinero real” a `frontend/src/App.jsx`, `frontend/src/pages/finance/Transfer.jsx` y `frontend/src/pages/finance/Dashboard.jsx`.
- [ ] T071 Validar startup, healthchecks, migraciones y estado de los servicios con `docker compose -f infra/compose.yaml up -d --build --wait` y el comando de migración descrito en `specs/002-financial-simulation/quickstart.md`.
- [ ] T072 Ejecutar suite backend objetivo y completa desde `backend/`; reportar exit code, passed/failed/skipped y cobertura de transferencias, locks, auditoría y permisos.
- [ ] T073 Ejecutar `npm.cmd --prefix frontend run build` y Playwright sobre el stack real; reportar exit code y journeys probados.
- [ ] T074 Ejecutar herramientas SAST/SCA existentes y Trivy sobre imágenes/archivos; registrar hallazgos nuevos y resolver los altos/críticos en archivos relevantes antes de completar la feature.
- [ ] T075 Revisar migración de base existente y base fresca, comprobar saldo de bienvenida único, reconciliación por moneda, append-only y ausencia de datos reales/secretos.

## Dependencias

- Fase 1 Setup → Fase 2 Fundamentos → historias.
- US1 requiere T004–T012; US2 depende de las cuentas US1 y de movimientos ledger; US3 requiere fundación y cuentas US1; US5 depende de US3; US6 depende de US3 y modelos de alerta; US4 depende solo de T004–T012.
- Orden MVP: US1 (cuenta y panel) → US3 (transferencia de bajo importe) → US2 (historial) → US5 (aprobaciones/límites) → US6 (fraude/alertas) → US4 (tarjetas).
- Las pruebas de migración y PostgreSQL real bloquean cualquier posting; no se permite saltarlas con SQLite/mock.

## Oportunidades paralelas

- Tras T001–T003, T004 y las pruebas de modelos T008 pueden avanzar en archivos separados.
- Tras T004–T012, dentro de US1 las pruebas contrato/aceptación pueden prepararse en paralelo; servicios/modelos deben integrarse antes de rutas.
- US4 puede desarrollarse después de fundación en paralelo a historias que no compartan componentes, aunque el MVP financiero de transferencias tiene prioridad.
- E2E de historias separadas pueden escribirse en paralelo si mantienen fixtures y rutas específicas; migraciones y merges del modelo son secuenciales.

## Estrategia de implementación

1. Construir un MVP vertical: cuenta bienvenida, panel y cuenta adicional propia (US1).
2. Agregar transferencias de bajo importe con libro contable/idempotencia/locks (US3) y movimiento asociado (US2).
3. Habilitar aprobaciones y límites antes de las operaciones que los requieren (US5).
4. Añadir motor de riesgo/alertas (US6), luego tarjetas ficticias (US4).
5. Cada etapa debe pasar sus pruebas PostgreSQL y E2E; no activar en la UI funciones cuyo endpoint aún no esté protegido/implementado.
