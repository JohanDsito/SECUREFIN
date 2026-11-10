# Investigación y decisiones: Simulación financiera SecureFin

## Libro contable y movimientos

**Decisión**: modelar cada transferencia completada como una transacción lógica con dos o más asientos inmutables, balanceados por moneda: débito en origen y crédito en destino. Registrar el crédito inicial como otra transacción balanceada contra una cuenta interna de fondos ficticios. Mantener el saldo mostrado como proyección actualizada dentro de la misma transacción; reconciliarlo con los asientos en pruebas/validación.

**Motivo**: el registro contable explica el origen y destino, evita que la historia se reescriba y permite comprobar que débito y crédito se compensan. Los `CHECK` por fila no bastan para imponer suma de varias filas.

**Alternativas**: modificar solo un `balance` (rechazado: no explica ni reconcilia movimientos); usar dos saldos sin registro transaccional (rechazado: estados parciales); añadir un proveedor de ledger (rechazado: rompe la simulación local y añade complejidad).

## Importe y moneda

**Decisión**: almacenar cantidades como enteros de unidad menor y códigos COP/USD; no usar flotantes. Cada transferencia requiere la misma moneda en ambas cuentas. Nunca sumar ni comparar importes de monedas distintas. USD usa políticas independientes acordadas; no se deriva ni persiste una tasa COP/USD.

**Motivo**: PostgreSQL advierte que `numeric` es exacto y los tipos de punto flotante son inexactos; el entero de unidad menor representa exactamente los importes admitidos y simplifica los invariantes.

**Alternativas**: `float` (rechazado por errores de redondeo); conversión automática (rechazada porque no hay servicio de tipo de cambio autorizado ni requisitos de valoración).

## Concurrencia y atomicidad

**Decisión**: dentro de `transaction.atomic`, bloquear con `SELECT FOR UPDATE` las cuentas origen y destino en orden determinista, revalidar saldo/políticas y escribir transferencia, asientos, saldos y eventos antes de commit. Tratar conflictos de unicidad de idempotencia con lectura del resultado ya persistido.

**Motivo**: una comprobación de saldo antes de la transacción tiene carreras. Bloqueos de fila serializan las operaciones que compiten por las mismas cuentas; una falla revierte las escrituras juntas.

**Alternativas**: lectura seguida de guardado sin bloqueo (rechazada); locks in-process (rechazados por múltiples workers/contenedores); `SERIALIZABLE` global (más abortos y complejidad de reintento sin beneficio para este alcance).

## Idempotencia

**Decisión**: clave obligatoria generada por el cliente, única por usuario y ámbito; guardar hash/fingerprint canónico de importe, moneda, origen, destino y descripción con resultado. Reutilización con el mismo payload devuelve la operación existente; con payload diferente devuelve conflicto.

**Motivo**: un cliente puede repetir la solicitud tras una respuesta perdida. La restricción única de PostgreSQL hace efectivo el control entre workers y procesos.

**Alternativas**: deduplicar solo en memoria (rechazado); aceptar toda repetición (rechazado: riesgo de doble débito).

## Aprobación y riesgo

**Decisión**: estados explícitos (`pending_approval`, `completed`, `rejected`); guardar aprobaciones como registros separados ligados a una huella inmutable de los detalles de la transferencia; no postear asientos hasta cumplir los umbrales. Rechazo es terminal. El servicio revalida saldo, vigencia de la política y estado de cuentas al completar.

**Motivo**: separa la intención de transferir del posting, impide cambiar los detalles luego de aprobados y evita que una aprobación antigua ignore un saldo consumido mientras espera.

**Alternativas**: debitar y "reservar" en la cuenta sin modelo de reserva (rechazado); permitir que una operación pendiente cambie (rechazado); aprobación por UI sin registro durable (rechazado).

## Auditoría financiera

**Decisión**: conservar el SecurityEvent existente para eventos de seguridad y añadir eventos/tipos explícitos del dominio financiero con el monto/moneda mínimos, IDs internos y correlación. Los asientos publicados no se actualizan/borran; aprobación, rechazo, reversiones y cambios de límites generan eventos append-only. No escribir PAN/CVV, cuentas completas, claves, credenciales ni tokens.

**Motivo**: seguir la auditoría existente sin crear una segunda semántica de identidad; las decisiones necesitan actor, resultado, motivo y referencia financiera.

**Alternativas**: incluir objetos/credenciales completos en metadata (rechazado por privacidad); editar un evento anterior para corregirlo (rechazado: se pierde evidencia); alegar inmutabilidad frente al propietario/superusuario DB (rechazado: documentar el límite de confianza).

## Tarjetas y límites de simulación

**Decisión**: las tarjetas son registros de estado/alias de demostración, sin PAN, CVV ni credenciales utilizables en red de pagos. La interfaz solo muestra la identificación ficticia enmascarada.

**Motivo**: congelar/descongelar tarjetas es suficiente para practicar el flujo de autorización y auditoría, sin crear secretos de pago imitables ni implicar que una tarjeta es utilizable.

**Alternativas**: generar números que pasen validaciones de redes de pago o almacenar CVV (rechazado, innecesario y confuso).

## Referencias

- PostgreSQL, transacciones: https://www.postgresql.org/docs/current/tutorial-transactions.html
- PostgreSQL, `numeric` y exactitud: https://www.postgresql.org/docs/current/datatype-numeric.html
- PostgreSQL, bloqueos de filas: https://www.postgresql.org/docs/current/explicit-locking.html#LOCKING-ROWS
- PostgreSQL, aislamiento: https://www.postgresql.org/docs/current/transaction-iso.html
- PostgreSQL, restricciones entre filas: https://www.postgresql.org/docs/current/ddl-constraints.html
- PostgreSQL, `INSERT ... ON CONFLICT`: https://www.postgresql.org/docs/current/sql-insert.html
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- NIST SP 800-53 Rev. 5, AC-5 Separation of Duties: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- Stripe, idempotent requests (ejemplo de implementación, no estándar): https://docs.stripe.com/api/idempotent_requests
- Modern Treasury, ledger transactions (ejemplo de implementación, no estándar): https://docs.moderntreasury.com/ledgers/docs/ledger-transactions-overview.md

Las referencias de proveedores explican patrones de implementación, no certifican el producto ni establecen requisitos regulatorios.
