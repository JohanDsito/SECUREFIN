# Contrato API: simulación financiera

Base: `/api/v1/finance`. JSON estricto; se rechazan campos desconocidos. Todas las rutas de Cliente requieren sesión IAM completa. Mutaciones requieren CSRF y `Origin` del mismo origen. Las operaciones de Admin requieren MFA y permiso de función; auditoría es solo lectura.

Errores comunes: 401 sin sesión completa; 403 rol/acción no permitidos; 404 recurso propio no encontrado o ajeno; 409 estado incompatible, límite, idempotencia reusada con otro payload o concurrencia no recuperable; 422 datos inválidos. Sin detalles internos ni existencia de recursos ajenos.

## Cliente

### `GET /dashboard`

Devuelve totales agrupados por moneda, cuentas propias resumidas, últimas operaciones, acciones pendientes del usuario y avisos no leídos. No agrega importes COP y USD.

### `GET /accounts`

Lista cuentas del propietario autenticado: `id`, `masked_number`, `type`, `currency`, `available_balance_minor`, `status`, `created_at`.

### `POST /accounts`

Abre cuenta adicional:

```json
{"type":"checking","currency":"USD"}
```

Respuesta 201 con cuenta propia activa y saldo cero. No se admite moneda fuera de COP/USD ni saldo/owner elegido por el cliente.

### `GET /accounts/{account_id}`

Devuelve la vista resumida de la cuenta propia, nunca número completo.

### `GET /transactions`

Query opcional: `from`, `to`, `status`, `kind`, `currency`, `account_id`, `page`. Todas las filas se limitan a cuentas propiedad del usuario; fechas ISO 8601, paginación acotada.

### `POST /transfers/preview`

```json
{"source_account_id":"uuid","destination_account_id":"uuid","amount_minor":100000,"currency":"COP","description":"Pago de demostración"}
```

Calcula validaciones y requiere de forma explícita una confirmación posterior. No reserva ni cambia saldo. Responde resumen, costos (cero), políticas que aplican, riesgo visible y si necesita aprobación.

### `POST /transfers`

Mismo cuerpo y cabecera obligatoria `Idempotency-Key` (UUID aleatorio). Valida de nuevo en el servidor; la respuesta identifica estado `completed`, `pending_approval` o `rejected`, monto/moneda, referencia y correlación. Nunca acepta estado, saldo o riesgo indicado por el cliente.

Repetición de clave con payload idéntico devuelve la misma operación; payload diferente devuelve 409.

### `GET /transfers/{transaction_id}`

Solo el creador/propietario autorizado puede consultar estado, resumen, motivos no sensibles y aprobaciones visibles para él.

### `GET /cards`, `POST /cards`, `POST /cards/{card_id}/freeze`, `POST /cards/{card_id}/unfreeze`

Gestión de tarjetas no utilizables en pago, solo del titular. Respuestas sin PAN/CVV; todas las mutaciones generan evento de auditoría.

## Administrador / Auditor

Permiso de función validado en backend. Administrador requiere MFA; cada acción de escritura es auditada. Auditor solo puede usar GET.

- `GET /admin/finance/approvals?status=pending_approval&page=1`
- `POST /admin/finance/transfers/{id}/approve` con motivo opcional seguro
- `POST /admin/finance/transfers/{id}/reject` con motivo requerido
- `GET /admin/finance/alerts?severity=&status=&from=&to=&page=`
- `GET /admin/finance/transactions?status=&currency=&from=&to=&page=`
- `GET /admin/finance/summary?from=&to=` devuelve estadísticas agregadas, sin cuentas completas.
- `GET /admin/finance/limits`
- `PUT /admin/finance/limits/{id}` cuerpo de campos permitidos, motivo obligatorio y versión esperada; conflicto de versión devuelve 409.
- `GET /admin/finance/rules`
- `PUT /admin/finance/rules/{code}` permite solo valores configurables del catálogo predefinido, con motivo y auditoría.

Una aprobación/decisión exige sesión completa con MFA fresco conforme a la política existente. El creador no puede aprobar; un Administrador distinto por cada aprobación; toda aprobación apunta a los detalles inmutables de esa solicitud. Umbrales de 2 aprobadores y monedas de la spec. Un Auditor puede leer listados/historial/alertas/resúmenes permitidos, no modificar políticas ni decidir.

## Respuestas y privacidad

- Campos monto siempre `*_minor` y moneda ISO; ninguna suma entre monedas.
- Números de cuenta visibles solo en formato enmascarado.
- Tarjeta es alias ficticio sin PAN/CVV; no existe endpoint de pago.
- `X-Request-ID` enlaza auditoría y logs; no reutilizar datos de usuario como identificador de correlación.
- Toda escritura genera evento de auditoría dentro de la misma transacción de dominio.
