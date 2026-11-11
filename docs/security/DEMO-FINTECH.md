# Demo en vivo de la fintech — paso a paso

Guion para mostrar **todas las funciones financieras** de SecureFin funcionando y, en cada una, el
**control de seguridad** que la protege. Complementa a [DEMO-EN-VIVO.md](DEMO-EN-VIVO.md), que cubre
los ataques por terminal (Nmap, DoS, SQLi, Wireshark).

Duración: **≈ 20 min**. Todo se hace en el navegador salvo donde se indica.

---

## Qué funciones tiene SecureFin

| Función | Pantalla | Quién | Control de seguridad que la acompaña |
|---|---|---|---|
| Abrir cuenta de cliente (con **$5.000.000 COP** de bienvenida) | `/register` | Cualquiera | Argon2id + lista de contraseñas filtradas; el rol no se puede elegir |
| Iniciar sesión y cerrar sesión | `/login` | Todos | Mensaje genérico, retrasos progresivos, cookie `__Host-` HttpOnly |
| MFA con app autenticadora + 10 códigos de recuperación | `/login/enroll`, `/profile` | Obligatorio Admin/Auditor, opcional Cliente | TOTP RFC 6238, secreto cifrado AES-256-GCM |
| Panel financiero: saldos por moneda, cuentas, actividad | `/finance` | Cliente | Solo ve **sus** cuentas (el servidor filtra por propietario) |
| Abrir cuentas adicionales (ahorros/corriente, COP/USD) | `/finance/accounts/new` | Cliente | Empiezan en $0; el cliente no puede fijar saldo ni dueño |
| Detalle de cuenta + ID público para recibir | `/finance/accounts/:id` | Cliente | Número enmascarado; cuenta ajena → 404 (anti-IDOR/BOLA) |
| Transferir entre cuentas propias o a otra persona | `/finance/transfer` | Cliente | Vista previa + confirmación, clave de idempotencia, límites |
| Aprobación de transferencias grandes | `/admin/finance/approvals` | Administrador (decide), Auditor (solo lee) | Segregación de funciones: el creador no aprueba; 1 o 2 admins distintos |
| Comprobante con línea de tiempo | `/finance/transfers/:id` | Cliente | Solo el creador puede consultarlo |
| Historial con filtros por estado | `/finance/activity` | Cliente | Paginado y limitado a cuentas propias |
| Sesiones activas y revocación | `/sessions` | Todos | Sesiones de servidor; revocar invalida la cookie al instante |
| Gestión de usuarios (crear Admin/Auditor, cambiar rol, desactivar) | `/admin/users` | Administrador | Solo por invitación con enlace de un uso; no puede auto-degradarse |
| Reinicio de MFA verificado | `/admin/mfa-resets` | Administrador | Verificación fuera de banda, 3 intentos |
| Centro de seguridad (pruebas en vivo) | `/seguridad` | Todos | Cabeceras, TLS, HttpOnly, SQLi, rate limiting |

**Política de aprobación** (`backend/apps/finance/policies/limits.py`):

| Importe COP | Importe USD | Resultado |
|---|---|---|
| hasta $1.000.000 | hasta US$250 | Se aplica al instante |
| hasta $5.000.000 | hasta US$1.250 | Queda **pendiente de 1 Administrador** |
| hasta $10.000.000 | hasta US$2.500 | Queda **pendiente de 2 Administradores distintos** |
| más de eso | más de eso | Rechazada (máximo por operación) |

Además: límite diario ($20.000.000), mensual ($100.000.000) y máximo 20 operaciones al día.

---

## 0. Preparación (antes de clase)

1. Stack levantado: `bash scripts/setup.sh` y `bash docs/security/demo/demo.sh estado`.
2. Ten abiertas **tres ventanas** del navegador (una normal y dos privadas/InPrivate, para tener tres
   sesiones independientes):
   - **Ventana A — Administrador** (`admin@lab.securefin.local`, ya activado y con MFA; ver README §2 paso 5).
   - **Ventana B — Cliente "Cliente Demo"** (`cliente@lab.securefin.local`).
   - **Ventana C — Cliente "Ana"** (`ana@lab.securefin.local`), la destinataria.
3. El móvil con la app autenticadora a mano.
4. Pestaña con el buzón **https://127.0.0.1:8025**.

> Consejo: haz el recorrido completo una vez la noche anterior. La transferencia grande consume
> parte del límite diario, pero sobra margen para repetirla varias veces.

---

## 1. Apertura de cuenta · 2 min (Semanas 1 y 4)

**Ventana C** → https://securefin.local → *Crear cuenta*.

1. Intenta primero la contraseña `password123` → el servidor la **rechaza** (demasiado corta y en la
   lista de contraseñas filtradas).
2. Usa `otra frase larga para ana 2026` → *Registrarse* → *Iniciar sesión*.
3. Entra en *Mi dinero*: Ana ya tiene **$5.000.000 COP** ficticios en una cuenta de ahorros.

**Explicar**: la contraseña se guarda con **Argon2id** y salt (lo muestra
`bash docs/security/demo/demo.sh cripto` al final). El panel lateral recuerda que enviar
`"role":"admin"` en el registro se rechaza: `bash docs/security/demo/demo.sh sqli` lo demuestra
(**400 campo no permitido**, asignación masiva).

## 2. Panel financiero y cuentas · 3 min (Semana 4: autorización por objeto)

**Ventana B** (Cliente Demo) → *Mi dinero*.

1. Muestra las tarjetas de saldo por moneda (COP y USD **nunca se suman**), las cuentas y la actividad.
2. *＋ Abrir cuenta* → **COP · Corriente** → la cuenta nueva aparece con **$0**.
3. Abre el detalle de la cuenta de ahorros: número **enmascarado** (`SF-DEMO-****-XXXX`) y el
   recuadro **"Para recibir transferencias"** con el ID público y el botón *Copiar ID*.

**Demo de IDOR/BOLA** (la más vistosa):

4. En la **Ventana C** (Ana) abre el detalle de su cuenta y pulsa **Copiar ID**.
5. En la **Ventana B** escribe en la barra de direcciones
   `https://securefin.local/finance/accounts/<ID de Ana>` → **"Cuenta no disponible"**.
6. **Explicar**: el servidor responde **404**, no 403, igual que para un ID inexistente: el atacante ni
   siquiera puede confirmar que la cuenta existe. Prueba automática: `backend/tests/security/test_bola.py`.

## 3. Transferencia entre cuentas propias · 2 min

**Ventana B** → *Transferir*.

1. **Desde**: la cuenta de ahorros. A la derecha aparece el **saldo disponible** y la **política de
   aprobación**.
2. **Hacia**: pulsa la tarjeta **"Mi cuenta corriente"** (se rellena el ID sola).
3. **Importe**: `250.000` · Descripción: `Ahorro a corriente` → *Revisar transferencia*.
4. Aparece **"Confirma los datos"** (comisión $0, *Procesamiento automático*). Hasta aquí **nada se
   ha movido**. → *Confirmar transferencia simulada* → **✔ Transferencia completada**.

**Explicar**: dos pasos (vista previa → confirmación) contra errores y *clickjacking*. Cada
confirmación lleva una **`Idempotency-Key`** aleatoria: si la red falla y el navegador reintenta, no
se cobra dos veces. El servidor **vuelve a validar** saldo, límites y dueño al confirmar.

## 4. Transferencia grande a otra persona → aprobación · 5 min (segregación de funciones + MFA)

**Ventana B** → *Transferir*.

1. **Desde**: ahorros · **ID de cuenta destino**: pega el **ID de Ana** · **Importe**: `2.000.000` ·
   Descripción `Pago grande a Ana` → *Revisar* → **Estado al confirmar: Pendiente de aprobación** →
   *Confirmar*.
2. *Ver estado de la transferencia* → comprobante con **línea de tiempo**: Solicitada ✓, Revisión ✓,
   **Aprobación pendiente**, Aplicada al saldo pendiente. El saldo **no** cambió.
3. **Ventana C** (Ana): su saldo sigue en $5.000.000.

**Ventana A** (Administrador) → *Aprobaciones*.

4. Aparece la solicitud: **$2.000.000 · 0/1 aprobaciones**, cuentas enmascaradas y el correo del creador.
5. Prueba primero **Rechazar sin motivo** → "Escribe un motivo breve para rechazar la operación." (y
   aunque alguien llamara a la API directamente, el servidor también exige el motivo).
6. Escribe el motivo `Verificado con el cliente por canal oficial` → **Aprobar**.
7. **Ventana B**: recarga el comprobante → todo en verde, **Completada**. **Ventana C**: Ana tiene
   ahora **$7.000.000**.

**Explicar**:
- El Cliente **no puede** aprobar su propia operación y el Administrador **no puede** crear
  transferencias: separación de funciones (control antifraude típico de un banco).
- Para decidir, el Administrador necesita **sesión con MFA**: sin el código TOTP no habría llegado a
  esta pantalla.
- Cada decisión queda en la **auditoría append-only**: `bash docs/security/demo/demo.sh auditoria`.

**Variante con 2 aprobadores** (si hay tiempo): crea un segundo Administrador en *Usuarios* (llega el
correo a Mailpit, se activa y configura su MFA). Ana, que ya tiene $7.000.000, transfiere
`6.000.000` a Cliente Demo → **0/2 aprobaciones**: el primer Admin aprueba (1/2), intenta aprobar otra
vez → "Este Administrador ya tomó una decisión"; el segundo Admin aprueba → se completa.

**Variante rechazo**: transfiere `1.500.000` → el Admin pulsa *Rechazar* con motivo → el comprobante
muestra **Rechazada** con la ✕ en la etapa de aprobación y el saldo no cambia.

## 5. Historial y límites · 2 min

**Ventana B** → *Movimientos*.

1. Filtros **Todas / Completadas / Pendientes / Rechazadas** (los filtra el servidor).
2. Cada fila: fecha, tipo, origen → destino **enmascarados**, estado y enlace al comprobante.
3. **Límite**: intenta transferir `11.000.000` → "El importe supera el máximo permitido para la moneda."
   Intenta transferir más de tu saldo → "Saldo insuficiente."

## 6. Roles y Zero Trust en la interfaz · 3 min (Semana 4: AAA)

1. **Ventana B** (Cliente): escribe `https://securefin.local/admin/users` → **"No tienes permiso"**
   (el servidor responde **403**; ocultar el botón no es la seguridad, la API es la que decide).
2. **Ventana A** (Admin) → *Usuarios*: crea un **Auditor** → correo de activación en Mailpit → el
   Auditor activa su cuenta y el sistema le **obliga a configurar MFA**. En *Aprobaciones* el Auditor
   ve la cola pero **sin botones** (solo lectura).
3. **Revocación inmediata**: en *Usuarios* el Admin **desactiva a Ana** → en la **Ventana C** recarga
   cualquier página → su sesión ya no vale.
4. Tu propia fila dice "Tu cuenta" y no tiene acciones: el último Administrador no puede degradarse
   ni desactivarse (409).

## 7. Sesiones y perfil · 1 min

**Ventana B** → clic en tu nombre → *Mi perfil*: rol, estado del MFA (puede activarlo un Cliente
también) → *Mis sesiones*: cada sesión con navegador, IP y última actividad. Inicia sesión con el
mismo usuario en otro navegador y ciérrala desde aquí con **Cerrar**: esa otra ventana queda fuera al
instante.

## 8. Cierre: Centro de seguridad · 2 min

`https://securefin.local/seguridad` → *Comprobar*, *Atacar login*, *Lanzar 80 peticiones*. Debajo, el
mapa de las 10 semanas con el comando de cada una para continuar con
[DEMO-EN-VIVO.md](DEMO-EN-VIVO.md).

---

## Si algo falla

| Síntoma | Causa | Solución |
|---|---|---|
| "No se encontró una cuenta disponible para la operación" | ID de destino mal pegado, o cuenta de otra moneda | Copia el ID con el botón *Copiar ID*; origen y destino deben ser de la misma moneda |
| "Se alcanzó el límite de frecuencia/diario" | Has repetido la demo muchas veces hoy | Usa otro cliente, o `bash scripts/setup.sh reset` para empezar de cero |
| El Admin no ve el botón Aprobar | Entró como Auditor, o la sesión no completó el MFA | Cierra sesión y entra con el Administrador + código TOTP |
| Login con 429 | Muchos intentos en el último minuto desde tu IP | Espera 1 minuto |
