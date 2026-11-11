# Modelo de datos: Simulación financiera

Los nombres son conceptuales; las tablas pertenecen al esquema privado `securefin`. Importe se representa en unidades menores enteras, con moneda obligatoria y restricciones positivas en las operaciones.

## Entidades

### DemoAccount

- `id`: UUID público; todos los endpoints validan propietario/rol aunque el ID sea válido.
- `owner_id`: FK IAM User; la cuenta interna de demostración no es visible ni operable por usuarios.
- `account_number_masked`: identificador sintético enmascarado; no es número bancario real.
- `account_type`: `checking` o `savings`.
- `currency`: `COP` o `USD`.
- `available_balance_minor`: entero no negativo en unidad menor de la moneda.
- `status`: `active`, `frozen` o `closed`.
- `created_at`, `updated_at`.
- Restricciones: índices por propietario/estado; no se permite transferir desde o hacia cuentas no activas.
- Provisionamiento: una cuenta COP con COP 5.000.000 de bienvenida por Cliente; cuentas adicionales empiezan en cero.

### FinancialTransaction

- `id`: UUID; `correlation_id`: UUID de trazabilidad.
- `kind`: `opening_credit`, `transfer`, `reversal`.
- `status`: `pending_approval`, `completed`, `rejected`.
- `creator_id`: propietario/actor.
- `source_account_id`, `destination_account_id`: referencias válidas para transferencias.
- `amount_minor`, `currency`, `description`.
- `idempotency_key`, `request_fingerprint`: único por creador/ámbito.
- `risk_level`, `risk_reasons`; detalle mínimo sin secretos.
- `created_at`, `resolved_at`, `rejection_reason`.
- Una transferencia exige origen diferente de destino, monto positivo, moneda igual a ambas cuentas. Las transacciones resueltas no se editan por el flujo normal.

### LedgerEntry

- `id`: UUID, `transaction_id`, `account_id`, `currency`, `amount_minor` firmado y `created_at`.
- Inmutable tras inserción; una transacción posteada requiere suma cero por moneda y al menos dos asientos.
- Cuenta de origen: asiento negativo; cuenta destino: positivo. Bienvenida: contrapartida cuenta interna.
- Los saldos deben reconciliarse con la suma de asientos por cuenta/moneda.
- Restricción de acceso: triggers deniegan UPDATE/DELETE/TRUNCATE y el rol runtime carece de esos privilegios; el propietario DB queda fuera de esta garantía.

### ApprovalDecision

- `id`, `transaction_id`, `approver_id`, `decision` (`approved`, `rejected`), `reason`, `created_at`.
- Restricción única `(transaction_id, approver_id)`; el creador no puede decidir su propia operación.
- Se fija una huella de los detalles aprobados; cambios invalidan una solicitud y exigen crear otra.
- Solo una sesión completa con MFA de un Administrador puede escribir una decisión.

### FinancialLimit

- `id`, `scope_type` (`user`, `role`, `operation`), `scope_id`, `currency`, `limit_kind` (`per_transaction`, `daily`, `monthly`, `frequency`), `amount_minor`/`count`, período, `updated_by`, `updated_at`, `reason`, `active`.
- Solo Administradores completos con MFA pueden modificar límites; cada cambio audita el valor anterior/nuevo y la razón.
- Valores iniciales acordados en la especificación: COP 10M/20M/100M; USD 2.5k/5k/25k; frecuencia configurada con política segura.
- La precedencia de políticas se define explícitamente (más restrictiva prevalece entre alcance de usuario/rol/global).

### RiskRule

- `id`, `code` único, `enabled`, umbral/ventana/peso, `action`, `updated_by`, `updated_at`.
- Conjunto inicial: velocidad de transferencias, reintentos de exceso de límite, monto inusual, nuevos destinatarios y login sospechoso reciente.
- Acciones: permitir, MFA adicional, revisión administrativa, rechazo.
- La regla solo activa flags/pasos de riesgo; nunca salta controles de saldo, propiedad, moneda, límites o aprobación.

### RiskAlert

- `id`, `transaction_id`, `rule_code`, `severity` (`low`, `medium`, `high`, `critical`), `reason`, `status`, `created_at`, `resolved_by`, `resolved_at`.
- Visible a Administrador autorizado; Auditor solo lectura conforme a la matriz.

### DemoCard

- `id`, `owner_id`, `display_alias` sintético y enmascarado, `status` (`active`, `frozen`, `closed`), `created_at`, `updated_at`.
- No tiene PAN, CVV, PIN, token de red ni campos de autorización de pagos.

### FinancialNotification

- `id`, `recipient_id`, `kind`, `transaction_id` opcional, mensaje de datos mínimos, `created_at`, `read_at`.
- No incluye credenciales, número de cuenta completo ni detalles de autenticación.

## Relaciones

```text
IAM User 1 ── N DemoAccount
IAM User 1 ── N FinancialTransaction (creator)
DemoAccount 1 ── N FinancialTransaction (source / destination)
FinancialTransaction 1 ── N LedgerEntry
FinancialTransaction 1 ── N ApprovalDecision
FinancialTransaction 1 ── N RiskAlert
IAM User 1 ── N ApprovalDecision / DemoCard / FinancialNotification
RiskRule 1 ── N RiskAlert (por code)
```

## Estados de transferencia

```text
creada → evaluación de reglas
  ├─ falla validación → rejected (sin asientos de transferencia)
  ├─ revisión/aprobación requerida → pending_approval
  │    ├─ rechazo autorizado → rejected (sin asientos)
  │    └─ aprobaciones requeridas → revalidar saldo/políticas y postear → completed
  └─ bajo riesgo/aprobación automática → revalidar y postear → completed
```

Solo `completed` tiene asientos de traslado. Rechazos y cambios de estado se auditan; la respuesta se persiste para idempotencia.
