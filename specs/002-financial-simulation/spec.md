# Especificación de funcionalidad: Simulación financiera SecureFin

**Rama de funcionalidad**: `002-financial-simulation`

**Creada**: 2026-11-10

**Estado**: Borrador

**Entrada**: El usuario solicita ampliar SecureFin Gateway, actualmente limitado a identidad y acceso, con una simulación fintech interactiva: panel financiero, cuentas de demostración, movimientos, transferencias, tarjetas virtuales, límites, aprobaciones, detección de fraude, alertas y auditoría.

## Escenarios de usuario y pruebas

### Historia 1: Consultar mi panel y mis cuentas (Prioridad: P1)

Como Cliente autenticado, quiero ver un panel financiero con mis cuentas, saldos y actividad reciente, y consultar los detalles de cada cuenta sin exponer información completa de la cuenta.

**Por qué esta prioridad**: Da a la simulación una experiencia financiera visible y permite verificar la propiedad de los datos.

**Prueba independiente**: Con dos clientes ficticios, cada uno consulta el panel, las cuentas y los movimientos; ninguno puede descubrir los datos del otro manipulando identificadores o filtros.

**Escenarios de aceptación**:

1. **Dado** un Cliente con cuentas de demostración, **cuando** abre el panel, **entonces** ve el saldo por moneda, el estado de cada cuenta y actividad reciente.
2. **Dado** un Cliente con más de una cuenta, **cuando** consulta una cuenta propia, **entonces** ve su tipo, moneda, saldo disponible, estado, fecha de apertura e identificador parcialmente enmascarado.
3. **Dado** un Cliente, **cuando** solicita una cuenta ajena, **entonces** no recibe datos de esa cuenta.
4. **Dado** un Cliente nuevo, **cuando** accede a la plataforma, **entonces** ya tiene una cuenta COP de demostración con saldo ficticio de COP 5.000.000; puede abrir cuentas adicionales con saldo inicial cero.
5. **Dado** un Cliente sin cuenta adicional de una moneda disponible, **cuando** abre una cuenta, **entonces** recibe una cuenta propia activa con saldo cero y moneda elegida, sujeta a las reglas de riesgo.

---

### Historia 2: Consultar y filtrar movimientos (Prioridad: P2)

Como Cliente, quiero revisar mis movimientos y filtrarlos por período, estado y tipo para entender qué pasó con mis fondos simulados.

**Por qué esta prioridad**: La actividad aporta contexto a los saldos y permite demostrar que las operaciones se registran de forma persistente.

**Prueba independiente**: Se crean movimientos ficticios para dos clientes; el primero filtra los propios por fecha, estado y tipo, y nunca ve los movimientos del segundo.

**Escenarios de aceptación**:

1. **Dado** un Cliente con movimientos, **cuando** abre la actividad, **entonces** ve fecha, referencia, tipo, importe, moneda, estado y cuentas parcialmente enmascaradas.
2. **Dado** un Cliente que combina filtros válidos, **cuando** consulta los resultados, **entonces** solo ve movimientos propios que cumplen todos los filtros.
3. **Dado** un filtro de fechas inválido o sin resultados, **cuando** consulta, **entonces** recibe validación clara o un estado vacío, sin errores internos.

---

### Historia 3: Crear y realizar una transferencia simulada (Prioridad: P1)

Como Cliente, quiero transferir fondos de una cuenta propia activa a otra cuenta de demostración, revisar un resumen y confirmar la operación sin que se mueva dinero real.

**Por qué esta prioridad**: Es la interacción financiera central de la demostración y ejercita las validaciones de saldo, límites, autorización y consistencia.

**Prueba independiente**: Se transfieren fondos entre cuentas ficticias compatibles, se verifica el saldo y el movimiento en ambos lados, y se comprueba que las solicitudes inválidas no cambian los saldos.

**Escenarios de aceptación**:

1. **Dado** un formulario válido, **cuando** el Cliente completa origen, destino, importe y descripción opcional, **entonces** antes de confirmar ve un resumen verificable de la operación.
2. **Dado** una transferencia confirmada entre cuentas activas, autorizadas y de la misma moneda, **cuando** todas las políticas se cumplen, **entonces** los saldos y movimientos se actualizan de forma consistente.
3. **Dado** fondos insuficientes, cuenta inactiva, cuenta de origen ajena, cuenta de destino inexistente, misma cuenta, moneda incompatible o importe inválido, **cuando** se confirma, **entonces** la operación no modifica ningún saldo y se presenta un motivo seguro.
4. **Dado** el mismo identificador de solicitud repetido, **cuando** llega más de una vez, **entonces** la transferencia se registra como máximo una vez y las repeticiones obtienen el mismo resultado.
5. **Dado** un importe o volumen que excede una política, **cuando** se confirma, **entonces** se rechaza o se enruta a aprobación conforme a la política, sin debitar fondos prematuramente.
6. **Dado** cualquier resultado, **cuando** el Cliente consulta sus movimientos, **entonces** puede ver el registro persistido de la operación, sin secretos ni datos completos de las cuentas.

---

### Historia 4: Gestionar tarjetas virtuales de demostración (Prioridad: P3)

Como Cliente, quiero consultar mis tarjetas virtuales ficticias y congelarlas o descongelarlas para explorar un flujo de autoservicio sin credenciales de pago reales.

**Por qué esta prioridad**: Amplía la experiencia de fintech sin conectarse a redes de tarjetas ni procesar compras reales.

**Prueba independiente**: Un Cliente consulta, congela y descongela una tarjeta propia; un segundo cliente no puede leer ni cambiar esa tarjeta.

**Escenarios de aceptación**:

1. **Dado** un Cliente con una tarjeta virtual, **cuando** consulta la tarjeta, **entonces** ve sus datos ficticios con la información sensible enmascarada y el estado.
2. **Dado** una tarjeta activa propia, **cuando** el Cliente la congela o descongela, **entonces** el estado cambia una sola vez y queda registrado.
3. **Dado** un Cliente que manipula el identificador de tarjeta, **cuando** intenta consultar o cambiar una tarjeta ajena, **entonces** la operación es denegada.
4. **Dado** cualquier dato de tarjeta, **cuando** se muestra o registra un evento, **entonces** nunca se expone un número de tarjeta real ni un código de seguridad.

---

### Historia 5: Administrar límites y revisar operaciones (Prioridad: P2)

Como Administrador autenticado y con MFA, quiero consultar operaciones que requieren aprobación, revisar alertas y cambiar políticas de límites para controlar la simulación. Como Auditor, quiero consultar los registros permitidos sin poder tomar decisiones ni modificar operaciones.

**Por qué esta prioridad**: Hace demostrables los controles de doble aprobación, separación de funciones y respuesta ante riesgos.

**Prueba independiente**: Se crean operaciones de distintos importes y niveles de riesgo; los administradores aprueban o rechazan según la política, y un auditor consulta el historial sin modificarlo.

**Escenarios de aceptación**:

1. **Dado** una operación bajo el umbral automático y de bajo riesgo, **cuando** satisface todos los controles, **entonces** se procesa automáticamente.
2. **Dado** una operación dentro de un rango con aprobación, **cuando** la crea un Cliente, **entonces** no se debita ni acredita saldo hasta obtener las aprobaciones requeridas.
3. **Dado** una operación pendiente, **cuando** el creador intenta aprobarla, un mismo Administrador intenta aprobarla dos veces o una aprobación carece de sesión completa con MFA, **entonces** la aprobación es rechazada.
4. **Dado** una operación que requiere dos aprobaciones, **cuando** la aprueban dos Administradores distintos, **entonces** se procesa una sola vez y el registro de decisiones se conserva.
5. **Dado** una operación rechazada, **cuando** se consulta su historial, **entonces** se conservan el estado y el motivo, sin permitir que la operación se altere después.
6. **Dado** un Administrador autorizado que cambia un límite, **cuando** guarda un valor válido, **entonces** queda vigente y se registra quién lo cambió, cuándo y por qué.
7. **Dado** un Auditor, **cuando** consulta operaciones, alertas e historial, **entonces** tiene solo permisos de lectura y no puede aprobar, rechazar ni cambiar límites.
8. **Dado** un Cliente, **cuando** solicita funciones de operación administrativa, **entonces** el servidor las deniega aunque intente usar directamente la interfaz o la API.

---

### Historia 6: Detectar actividad sospechosa y consultar alertas (Prioridad: P2)

Como sistema y como operador autorizado, quiero evaluar transferencias con reglas de riesgo comprensibles, dejar una alerta con el motivo y aplicar la acción asociada a la severidad.

**Por qué esta prioridad**: La gestión del riesgo diferencia una simulación fintech de un listado de saldos y da evidencia de controles de seguridad.

**Prueba independiente**: Se ejecutan escenarios controlados que disparan cada regla; se verifica la evaluación, acción, alerta y registro, y se comprueba que no se completa una operación bloqueada.

**Escenarios de aceptación**:

1. **Dado** una operación que infringe una regla de bajo riesgo, **cuando** se evalúa, **entonces** se permite únicamente si satisface las políticas restantes.
2. **Dado** una operación que requiere MFA adicional, revisión administrativa o rechazo, **cuando** se evalúa, **entonces** no se procesa hasta completar el paso requerido o queda rechazada con motivo.
3. **Dado** actividad sospechosa, **cuando** el panel autorizado muestra la alerta, **entonces** presenta nivel, regla activada, motivo seguro, estado y fecha.
4. **Dado** una notificación financiera, **cuando** se muestra, **entonces** informa del evento sin revelar secretos, credenciales ni datos completos de cuenta.

## Casos límite

- Dos transferencias concurrentes no pueden gastar el mismo saldo disponible.
- Una repetición de una solicitud idempotente no crea otro débito, crédito, movimiento ni decisión.
- Una operación con moneda distinta entre origen y destino se rechaza mientras no exista conversión explícitamente habilitada.
- Los importes cero, negativos, con precisión inválida o por encima del límite no generan cambios contables.
- Una cuenta cerrada o suspendida no puede enviar ni recibir transferencias.
- Un fallo entre el débito y el crédito deja ambos saldos intactos.
- Los límites diarios y mensuales se evalúan considerando zona horaria y período definidos, sin evitarse mediante solicitudes concurrentes.
- Un usuario no autorizado no obtiene confirmación de si existe una cuenta, tarjeta u operación de otra persona.
- Un Administrador no aprueba su propia operación ni reemplaza la aprobación de otra persona.
- Las alertas, notificaciones y auditoría no contienen contraseñas, códigos MFA, tokens, números de cuenta completos o números de tarjeta completos.
- Las funciones financieras no están disponibles para sesiones incompletas ni para usuarios sin rol y permisos vigentes.

## Requisitos

### Requisitos funcionales

- **FR-FIN-001**: El sistema DEBE provisionar a cada Cliente una cuenta COP de demostración con saldo inicial ficticio de COP 5.000.000 y permitir abrir cuentas adicionales COP o USD con saldo inicial cero; cada cuenta tendrá identificador único, número enmascarado, tipo, moneda ISO 4217, saldo disponible, estado y fecha de apertura.
- **FR-FIN-002**: El sistema DEBE restringir la consulta y operación de cuentas al propietario, salvo funciones administrativas explícitamente autorizadas y auditadas.
- **FR-FIN-003**: El Cliente DEBE poder consultar movimientos con importe, moneda, fecha, tipo, estado, referencia y cuentas de origen y destino parcialmente enmascaradas, y filtrarlos por período, estado y tipo.
- **FR-FIN-004**: El sistema DEBE permitir preparar, revisar y confirmar transferencias únicamente entre cuentas de demostración activas, autorizadas y compatibles.
- **FR-FIN-005**: El sistema DEBE validar importe positivo, saldo suficiente, límites aplicables, cuentas distintas, moneda permitida y autorización sobre las cuentas antes de ejecutar una transferencia.
- **FR-FIN-006**: El sistema DEBE asegurar consistencia contable: una transferencia completada cambia el débito, el crédito y sus movimientos como una sola operación lógica; un fallo no deja saldos parciales.
- **FR-FIN-007**: El sistema DEBE admitir claves de idempotencia para evitar que solicitudes repetidas creen transferencias duplicadas.
- **FR-FIN-008**: Las transferencias DEBEN ser simuladas y no podrán invocar servicios bancarios, redes de pago ni dinero real.
- **FR-FIN-009**: El sistema DEBE identificar monedas mediante ISO 4217, soportar COP y USD y rechazar la conversión entre monedas salvo que se incorpore y autorice explícitamente una política de cambio.
- **FR-FIN-010**: El sistema DEBE aplicar límites máximos por transacción, diarios y mensuales, y límites de frecuencia, configurables por usuario, rol u operación por Administradores autorizados; los valores iniciales para COP serán 10.000.000 por operación, 20.000.000 diarios y 100.000.000 mensuales, y para USD serán 2.500 por operación, 5.000 diarios y 25.000 mensuales.
- **FR-FIN-011**: Los límites DEBEN identificarse como políticas editables de demostración, no como límites regulatorios ni promesas de servicio financiero real.
- **FR-FIN-012**: El sistema DEBE automatizar operaciones de bajo riesgo hasta COP 1.000.000 o USD 250; exigir una aprobación administrativa para importes superiores y hasta COP 5.000.000 o USD 1.250; exigir dos Administradores distintos para importes superiores y hasta COP 10.000.000 o USD 2.500; y rechazar importes por encima del máximo de la moneda.
- **FR-FIN-013**: Una operación pendiente de aprobación NO DEBE modificar saldos hasta que reúna todas las aprobaciones requeridas; al completarse solo podrá procesarse una vez.
- **FR-FIN-014**: El sistema DEBE impedir la autoaprobación del creador, aprobaciones duplicadas por la misma persona y aprobaciones sin sesión autenticada completamente y MFA vigente.
- **FR-FIN-015**: Las decisiones de aprobación o rechazo DEBEN conservar autor, fecha y motivo; una operación resuelta no podrá modificarse ni reabrirse mediante el flujo normal.
- **FR-FIN-016**: El motor de riesgo DEBE evaluar al menos frecuencia elevada, intentos repetidos de exceder límites, importe inusual, destinatarios nuevos en poco tiempo y eventos recientes de autenticación sospechosos.
- **FR-FIN-017**: Cada evaluación de riesgo DEBE generar nivel bajo, medio, alto o crítico, regla activada, motivo y acción; las acciones posibles incluyen continuación, MFA adicional, revisión administrativa o rechazo.
- **FR-FIN-018**: El sistema DEBE generar alertas ante transferencias, aprobaciones requeridas, resoluciones, límites alcanzados, actividad sospechosa y cambios de límites, minimizando los datos revelados.
- **FR-FIN-019**: El panel de riesgos DEBE permitir a Administradores autorizados consultar aprobaciones pendientes, rechazos, alertas, historial de decisiones y estadísticas agregadas.
- **FR-FIN-020**: Los Auditores DEBEN poder consultar, según el permiso otorgado, las operaciones y alertas; no podrán modificar límites ni aprobar o rechazar operaciones.
- **FR-FIN-021**: Toda operación financiera y toda decisión administrativa DEBE generar un registro append-only con actor, tipo, identificador de operación, fecha y hora, importe y moneda pertinentes, resultado, motivo pertinente e identificador de correlación.
- **FR-FIN-022**: El sistema DEBE ofrecer tarjetas exclusivamente virtuales y ficticias, con información sensible enmascarada y opciones de congelación y descongelación restringidas al propietario y auditadas.
- **FR-FIN-023**: La interfaz DEBE mostrar el panel financiero, cuentas propias, actividad, flujo de transferencia y, según el rol, tarjetas, aprobación, alertas y gestión de límites.
- **FR-FIN-024**: Las operaciones financieras DEBEN respetar las reglas IAM existentes: autenticación completa, MFA de roles privilegiados, autorización de función y objeto, CSRF, respuestas que no revelen recursos ajenos y auditoría.

### Entidades clave

- **Cuenta de demostración**: propiedad, identificador público, número enmascarado, tipo, moneda, saldo, estado y fechas.
- **Movimiento**: referencia a una cuenta, tipo, importe, moneda, estado, descripción y fecha.
- **Transferencia**: cuentas de origen/destino, propietario creador, importe, moneda, idempotencia, estado, riesgo y correlación.
- **Decisión de aprobación**: operación, Administrador que decide, resultado, motivo y fecha; una aprobación por persona y operación.
- **Política de límites**: alcance, moneda, período, importe o frecuencia, vigencia y actor que la cambió.
- **Evaluación de riesgo y alerta**: reglas activadas, nivel, motivo, acción tomada, estado y fechas.
- **Tarjeta virtual de demostración**: titular, datos ficticios parcialmente enmascarados, estado y fechas.
- **Evento de auditoría financiera**: actor, operación, resultado, atributos mínimos, motivo y correlación; no editable por flujos normales.

## Criterios de éxito

### Resultados medibles

- **SC-FIN-001**: Un Cliente puede entender sus saldos por moneda y abrir su lista de movimientos en menos de 30 segundos desde el panel.
- **SC-FIN-002**: En pruebas de transferencia válidas, débito, crédito y movimientos concuerdan en el 100 % de los casos; en rechazos o fallos no se altera ningún saldo.
- **SC-FIN-003**: Repetir 100 veces una misma solicitud idempotente produce como máximo una transferencia y un conjunto de movimientos.
- **SC-FIN-004**: Todas las pruebas de acceso cruzado a cuentas, movimientos, transferencias y tarjetas deniegan el acceso y no revelan datos del propietario ajeno.
- **SC-FIN-005**: Todos los umbrales de límites y aprobaciones tienen pruebas en el valor inmediatamente inferior, en el umbral y en el valor inmediatamente superior.
- **SC-FIN-006**: Ninguna operación de alto riesgo o pendiente se liquida antes de satisfacer su paso de MFA o aprobación.
- **SC-FIN-007**: El 100 % de operaciones, cambios de política, decisiones y alertas de riesgo produce eventos de auditoría consultables por roles autorizados.
- **SC-FIN-008**: El 100 % de notificaciones, vistas y eventos de auditoría evita credenciales, secretos MFA y datos completos de cuenta o tarjeta.
- **SC-FIN-009**: Ninguna operación de la funcionalidad genera una conexión a proveedores de dinero, bancos o tarjetas reales.

## Supuestos

- La funcionalidad es un laboratorio académico local con identidades y datos ficticios; no es una entidad financiera ni presta servicios regulados.
- La autenticación, las sesiones, los roles, MFA, la auditoría y el correo local existentes se reutilizan; la seguridad de las operaciones se decide en el servidor.
- COP y USD son monedas identificadas por separado. No se realizará conversión de divisas en esta versión.
- El Administrador debe tener MFA activo y una sesión completa para gestionar límites o decisiones; el Auditor solo tiene lectura.
- Las políticas de montos propuestas por el usuario se expresan en COP. La aplicación de importes y umbrales a USD requiere confirmación.
- Los saldos son datos demostrativos. El modo de apertura y financiación inicial de las cuentas requiere confirmación antes de desarrollar transferencias utilizables.
- No se conectarán rieles de pago, bancos, redes de tarjetas, conversores de divisas ni servicios externos de identidad.
- La especificación base 001 continúa describiendo IAM; esta funcionalidad amplía el producto en una especificación independiente.

## Decisiones confirmadas

- Cada Cliente recibe al inicio una cuenta COP de demostración con COP 5.000.000 ficticios; las cuentas adicionales comienzan con saldo cero. No hay función de abono manual.
- Los límites USD son USD 2.500 por operación, USD 5.000 diarios y USD 25.000 mensuales. Las aprobaciones USD son automáticas hasta USD 250, una aprobación hasta USD 1.250 y dos aprobaciones hasta USD 2.500. Son umbrales fijos de demostración, no una conversión de moneda ni una tasa de cambio.
