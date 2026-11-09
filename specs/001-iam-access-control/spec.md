# Feature Specification: Sistema de Identidad y Control de Acceso (IAM)

**Feature Branch**: `001-iam-access-control`

**Created**: 2026-11-08

**Status**: Draft

**Input**: User description: "FEATURE 001 — Sistema de identidad y control de acceso (IAM) de SecureFin
Gateway: registro, inicio y cierre de sesión, contraseñas con Argon2id, gestión de roles y permisos
(Cliente, Administrador, Auditor), MFA TOTP obligatorio para administradores, protección frente a
intentos repetidos, control de acceso a recursos propios (BOLA/IDOR), registro de eventos de
autenticación y autorización, y recuperación segura de acceso. Solo identidades ficticias; sin
cuentas ni transferencias; sin decidir aún la arquitectura interna de autenticación."

## Clarifications

### Session 2026-11-08

- Q: ¿El MFA es obligatorio para los Auditores? → A: Sí. El MFA es obligatorio para todo rol
  distinto de Cliente (Administrador y Auditor) y para cualquier rol privilegiado futuro; para el
  Cliente es opcional.
- Q: ¿Cómo se recupera el acceso ante la pérdida del dispositivo TOTP? → A: Con ambos mecanismos:
  códigos de recuperación de un solo uso y, como alternativa, reinicio administrativo del MFA. La
  recuperación del último Administrador usa un procedimiento extraordinario desde la consola del
  entorno controlado.
- Q: ¿Por qué canal se entrega el token de recuperación? → A: Por un buzón de correo de laboratorio
  local que captura los correos (decisión: Mailpit), sin envío a servicios externos.
- Ajustes adicionales aprobados: contraseñas de 15 a 128 caracteres; retrasos progresivos y
  limitación por cuenta y por origen en lugar de bloqueo rígido (enfriamiento máximo de 15 minutos);
  sin credenciales predeterminadas ni interfaz pública para crear administradores.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Registro, inicio y cierre de sesión de clientes (Priority: P1)

Una persona (con identidad ficticia) se registra como Cliente proporcionando un identificador de
correo, un nombre y una contraseña. Después inicia sesión con sus credenciales, accede a su área
personal y cierra la sesión cuando termina. Las contraseñas nunca se guardan en texto plano, se
admiten gestores de contraseñas y los errores de autenticación no revelan si una cuenta existe.

**Why this priority**: sin identidad autenticada no existe ningún otro control; es la base mínima
viable de la plataforma y de todas las features posteriores.

**Independent Test**: puede probarse completamente registrando un cliente ficticio, iniciando
sesión, accediendo a su perfil, cerrando sesión y comprobando que tras el cierre ya no puede
acceder; aporta valor como puerta de entrada segura.

**Acceptance Scenarios**:

1. **Given** un visitante sin cuenta, **When** se registra con datos válidos y una contraseña que
   cumple la política, **Then** se crea una cuenta con rol Cliente y la contraseña queda almacenada
   solo como hash Argon2id.
2. **Given** un visitante, **When** intenta registrarse indicando un rol distinto de Cliente (por
   ejemplo, manipulando la petición), **Then** el campo se ignora o se rechaza y la cuenta, si se
   crea, tiene únicamente el rol Cliente.
3. **Given** un visitante, **When** envía una contraseña de menos de 15 caracteres, de más de 128, o
   incluida en la lista de bloqueo (común, esperada o comprometida), **Then** el registro se rechaza
   en el servidor con un mensaje que explica la regla incumplida.
4. **Given** un visitante que usa un gestor de contraseñas, **When** pega o autocompleta la
   contraseña, **Then** el sistema lo permite.
5. **Given** un cliente registrado, **When** inicia sesión con credenciales correctas, **Then**
   obtiene una sesión autenticada y accede a su área personal.
6. **Given** un identificador inexistente o una contraseña incorrecta, **When** se intenta iniciar
   sesión, **Then** el sistema responde con el mismo mensaje genérico en ambos casos.
7. **Given** un cliente con sesión activa, **When** cierra sesión, **Then** la sesión queda revocada
   y cualquier intento posterior de usarla es rechazado.
8. **Given** una sesión inactiva durante más de 15 minutos o creada hace más de 8 horas, **When** el
   usuario intenta usarla, **Then** se rechaza y debe autenticarse de nuevo.

---

### User Story 2 - Acceso según rol y solo a recursos propios (Priority: P2)

Cada usuario puede ejecutar únicamente las funciones permitidas por su rol y operar únicamente
sobre sus propios recursos (perfil, sesiones y configuración de seguridad). Un Cliente no puede ver
ni modificar los datos de otro Cliente aunque conozca o adivine su identificador, ni invocar
funciones administrativas o de auditoría. Todas las verificaciones se hacen en el servidor.

**Why this priority**: el control de acceso roto (BOLA/IDOR y BFLA) es el riesgo principal de las
APIs; sin este control la autenticación no protege los datos.

**Independent Test**: con usuarios ficticios precargados de cada rol, se intenta acceder a recursos
de otro usuario cambiando identificadores y a funciones de otros roles; todas las peticiones no
autorizadas deben ser denegadas y registradas.

**Acceptance Scenarios**:

1. **Given** el Cliente A autenticado, **When** consulta o modifica su propio perfil, **Then** la
   operación se permite.
2. **Given** el Cliente A autenticado, **When** solicita el perfil, las sesiones o la configuración
   de seguridad del Cliente B usando el identificador de B, **Then** el acceso se deniega sin revelar
   si el recurso existe, y se registra un evento de acceso denegado.
3. **Given** un Cliente autenticado, **When** invoca una función administrativa o de auditoría
   (aunque la interfaz no la muestre), **Then** el servidor la deniega.
4. **Given** un Auditor autenticado, **When** intenta modificar o eliminar un evento de seguridad,
   **Then** la operación se deniega.
5. **Given** un Administrador autenticado, **When** intenta consultar el contenido del registro de
   auditoría, **Then** la operación se deniega (separación de funciones).
6. **Given** una petición sin sesión válida, **When** intenta acceder a cualquier recurso protegido,
   **Then** se deniega.
7. **Given** un Cliente que modifica su perfil, **When** incluye campos no permitidos (rol, estado de
   la cuenta, estado de MFA), **Then** esos campos no se aplican.

---

### User Story 3 - Segundo factor TOTP y códigos de recuperación (Priority: P3)

Un usuario configura un segundo factor basado en códigos temporales (TOTP) con una aplicación
autenticadora y recibe, una sola vez, un conjunto de códigos de recuperación de un solo uso. A
partir de entonces, para iniciar sesión necesita la contraseña y un código TOTP válido o, si perdió
su dispositivo, uno de sus códigos de recuperación. Para los roles Administrador y Auditor el MFA es
obligatorio: no pueden acceder a ninguna funcionalidad protegida sin haberlo configurado.

**Why this priority**: el MFA mitiga el robo de contraseñas y es requisito constitucional para los
roles privilegiados; las funciones administrativas (US4) y de auditoría (US6) dependen de él.

**Independent Test**: se configura TOTP para un usuario ficticio, se inicia sesión con código válido
(acceso concedido) y con códigos inválidos, vencidos o reutilizados (acceso denegado); se usa un
código de recuperación una vez (concedido) y de nuevo (denegado); se comprueba que un Auditor o
Administrador sin MFA no accede a funcionalidades protegidas.

**Acceptance Scenarios**:

1. **Given** un usuario autenticado sin MFA, **When** inicia la configuración de TOTP y confirma un
   código válido generado por su aplicación, **Then** el MFA queda activado y se le muestran sus
   códigos de recuperación una única vez.
2. **Given** un usuario que inicia la configuración, **When** no confirma un código válido,
   **Then** el MFA no se activa y no se generan códigos de recuperación.
3. **Given** un usuario con MFA activo, **When** introduce la contraseña correcta y un código TOTP
   válido, **Then** obtiene la sesión autenticada.
4. **Given** un usuario con MFA activo, **When** introduce la contraseña correcta y un código
   incorrecto, vencido o ya utilizado, **Then** el acceso se deniega y el intento cuenta como fallido.
5. **Given** un usuario con MFA activo que perdió su dispositivo, **When** introduce la contraseña y
   un código de recuperación no usado, **Then** obtiene la sesión, ese código queda invalidado y se le
   indica cuántos códigos le quedan.
6. **Given** un código de recuperación ya usado o de un conjunto anterior, **When** se intenta usar,
   **Then** se rechaza.
7. **Given** un usuario autenticado con MFA, **When** solicita un nuevo conjunto de códigos de
   recuperación confirmando contraseña y un código TOTP válido, **Then** se genera un conjunto nuevo,
   se muestra una sola vez y el anterior queda invalidado.
8. **Given** un usuario que inició sesión con un código de recuperación, **When** reconfigura su TOTP
   confirmando su contraseña y un código del nuevo dispositivo, **Then** el secreto anterior y los
   códigos anteriores quedan invalidados y se genera un conjunto nuevo.
9. **Given** un Administrador o Auditor sin MFA configurado, **When** inicia sesión, **Then** solo
   puede completar la configuración de MFA y no accede a ninguna otra funcionalidad hasta verificarlo.
10. **Given** un Administrador o Auditor con MFA activo, **When** intenta desactivarlo, **Then** la
    operación se rechaza; un Cliente puede desactivarlo confirmando contraseña y un código válido.

---

### User Story 4 - Administración de usuarios, roles y reinicio de MFA (Priority: P4)

Un Administrador (con MFA) consulta la lista de usuarios, crea cuentas de Administrador o Auditor,
asigna o cambia roles, desactiva o reactiva cuentas y, como mecanismo alternativo de recuperación,
reinicia el MFA de otro usuario tras verificar su identidad. El primer Administrador y la
recuperación del último Administrador se gestionan solo mediante procedimientos ejecutados desde la
consola del entorno controlado.

**Why this priority**: permite operar la plataforma con mínimo privilegio, pero solo es necesario
una vez que existen identidades, RBAC y MFA.

**Independent Test**: un Administrador ficticio con MFA cambia el rol de un usuario, desactiva otra
cuenta y reinicia el MFA de un tercero; se verifica el efecto inmediato, el registro de los eventos,
la notificación en el buzón de laboratorio y que un usuario no administrador no puede realizar estas
acciones.

**Acceptance Scenarios**:

1. **Given** un Administrador autenticado con MFA, **When** asigna el rol Auditor a un usuario,
   **Then** el cambio se aplica, las sesiones existentes de ese usuario se revocan, se le exige
   configurar MFA en su siguiente acceso y se registra el evento.
2. **Given** un Administrador, **When** desactiva una cuenta, **Then** sus sesiones activas se
   revocan de inmediato y la cuenta no puede iniciar sesión.
3. **Given** un Administrador, **When** intenta cambiar su propio rol, desactivar su propia cuenta o
   reiniciar su propio MFA, **Then** la operación se rechaza.
4. **Given** que solo queda un Administrador activo, **When** se intenta degradarlo o desactivarlo,
   **Then** la operación se rechaza.
5. **Given** un Administrador, **When** crea una cuenta de Administrador o Auditor, **Then** el nuevo
   usuario recibe en el buzón de laboratorio un enlace de activación de un solo uso, establece su
   propia contraseña y configura MFA antes de operar.
6. **Given** un Administrador con MFA activo que verificó la identidad de un usuario, **When**
   reinicia su MFA confirmando su propio código TOTP en ese momento, **Then** el secreto TOTP y los
   códigos de recuperación del usuario se invalidan, sus sesiones se revocan, se le notifica en el
   buzón de laboratorio, se registran solicitante, autorizador, método de verificación y fecha, y el
   usuario debe configurar MFA de nuevo si su rol lo exige.
7. **Given** un MFA reiniciado por un Administrador, **When** el usuario afectado intenta acceder,
   **Then** sigue necesitando su contraseña: el reinicio no concede acceso ni revela o cambia la
   contraseña, y el Administrador nunca ve el nuevo secreto ni los nuevos códigos.
8. **Given** un entorno sin Administradores, **When** se ejecuta el procedimiento de inicialización
   desde la consola del entorno controlado, **Then** se crea el primer Administrador sin credenciales
   predeterminadas, debe configurar MFA en su primer acceso y se registra el evento.
9. **Given** que el último Administrador perdió su contraseña o su MFA, **When** se ejecuta el
   procedimiento extraordinario desde la consola del entorno controlado, **Then** se restablece su
   acceso con las mismas garantías que el reinicio administrativo y se registra el evento; no existe
   ninguna interfaz web ni de API para este procedimiento.

---

### User Story 5 - Protección frente a intentos repetidos de autenticación (Priority: P5)

El sistema detecta intentos de autenticación fallidos sobre una misma cuenta o desde un mismo
origen y aplica retrasos progresivos y limitación de tasa, sin bloqueo rígido que permita a un
atacante dejar a la víctima sin acceso, sin revelar si la cuenta existe y registrando los eventos
anómalos.

**Why this priority**: mitiga ataques de fuerza bruta y relleno de credenciales; refuerza US1 y US3
pero no es necesario para demostrar el flujo básico.

**Independent Test**: se ejecuta una serie automatizada de intentos fallidos contra una cuenta
ficticia y desde un mismo origen contra varias cuentas; se verifica la aplicación de retrasos, su
límite máximo de 15 minutos, su expiración y el registro de eventos anómalos.

**Acceptance Scenarios**:

1. **Given** una cuenta, **When** acumula 5 fallos consecutivos de autenticación (contraseña,
   código TOTP o código de recuperación), **Then** cada intento siguiente requiere esperar un retraso
   creciente, que nunca supera 15 minutos.
2. **Given** una cuenta en periodo de retraso, **When** se recibe un intento antes de que termine,
   **Then** se rechaza sin evaluar las credenciales y con una respuesta genérica.
3. **Given** una cuenta con fallos acumulados, **When** el usuario se autentica correctamente tras
   el retraso, **Then** el contador de fallos se reinicia.
4. **Given** un mismo origen, **When** supera el umbral de intentos fallidos contra una o varias
   cuentas, **Then** sus intentos se limitan temporalmente y se registra un evento anómalo.
5. **Given** un identificador inexistente, **When** recibe intentos repetidos, **Then** el
   comportamiento observable es el mismo que para una cuenta existente.
6. **Given** un atacante que provoca fallos sobre la cuenta de una víctima, **When** termina el
   periodo de enfriamiento, **Then** la víctima puede volver a autenticarse; la recuperación de acceso
   sigue disponible en todo momento.

---

### User Story 6 - Registro de eventos y consulta por el Auditor (Priority: P6)

El sistema registra los eventos de autenticación, autorización y administración. El Auditor (con
MFA) los consulta y filtra por fecha, tipo de evento, resultado y usuario, sin poder modificarlos.
Los registros nunca contienen contraseñas, códigos, tokens ni secretos.

**Why this priority**: aporta trazabilidad e investigación de incidentes; los eventos se generan
desde las historias anteriores, por lo que su consulta es la última capa de control.

**Independent Test**: se generan eventos (inicio de sesión exitoso y fallido, acceso denegado,
cambio de rol, reinicio de MFA) con usuarios ficticios; el Auditor los consulta y filtra; se
inspeccionan los registros para confirmar la ausencia de datos sensibles y la imposibilidad de
modificarlos.

**Acceptance Scenarios**:

1. **Given** cualquier evento de la lista de FR-040, **When** ocurre, **Then** se registra con marca
   de tiempo, tipo, actor (identificador interno o seudonimizado), recurso, resultado y origen.
2. **Given** un Auditor autenticado con MFA, **When** consulta eventos con filtros, **Then** obtiene
   solo los eventos que cumplen los filtros.
3. **Given** cualquier evento registrado, **When** se inspecciona su contenido, **Then** no contiene
   contraseñas, códigos TOTP, secretos, códigos de recuperación, tokens ni identificadores de sesión.
4. **Given** un Cliente o un Administrador, **When** intenta consultar el registro de auditoría,
   **Then** se deniega.

---

### User Story 7 - Recuperación segura de contraseña (Priority: P7)

Un usuario que olvidó su contraseña solicita restablecerla. El sistema envía un token de un solo uso
y caducidad corta al buzón de correo de laboratorio, no revela si la cuenta existe y revoca las
sesiones anteriores al completar el cambio.

**Why this priority**: necesaria para la operación real, pero es la funcionalidad con más
superficie de abuso y depende de las anteriores (MFA, limitación de intentos, registro).

**Independent Test**: se solicita la recuperación para una cuenta ficticia existente y para una
inexistente (misma respuesta), se recupera el token desde el buzón de laboratorio, se completa el
restablecimiento y se verifica que el token no puede reutilizarse ni usarse vencido, que no aparece
en los registros y que las sesiones previas quedan revocadas.

**Acceptance Scenarios**:

1. **Given** cualquier identificador, existente o no, **When** se solicita la recuperación,
   **Then** la respuesta es idéntica en ambos casos.
2. **Given** una solicitud válida para una cuenta existente, **When** se emite el token, **Then** se
   entrega únicamente en el buzón de correo de laboratorio, es de un solo uso, caduca a los 15
   minutos y solo su hash queda almacenado.
3. **Given** un token válido, **When** el usuario establece una nueva contraseña que cumple la
   política, **Then** la contraseña cambia, el token queda invalidado y todas las sesiones previas
   se revocan.
4. **Given** un token ya usado, vencido, sustituido por uno más reciente o alterado, **When** se
   intenta usar, **Then** se rechaza.
5. **Given** un usuario con MFA activo, **When** restablece su contraseña, **Then** el MFA sigue
   activo y se exige en el siguiente inicio de sesión.

---

### Edge Cases

- Registro con un identificador ya existente: se rechaza sin crear duplicados; el riesgo residual de
  enumeración en el registro se mitiga con limitación de tasa y se documenta en el análisis STRIDE.
- Contraseña de más de 128 caracteres para provocar consumo de recursos en el hash: se rechaza.
- Contraseña que contiene el identificador, el nombre del usuario o el nombre del servicio: se
  rechaza como contraseña esperada.
- Contraseñas con caracteres Unicode o espacios: se aceptan y se tratan de forma consistente en
  registro y en inicio de sesión.
- Código TOTP con desfase de reloj: se acepta como máximo un intervalo de tolerancia antes o
  después; un código ya usado no se acepta de nuevo dentro de su ventana (prevención de repetición).
- Usuario que agota sus códigos de recuperación: puede generar un conjunto nuevo con contraseña y
  TOTP; si además perdió el dispositivo, recurre al reinicio administrativo.
- Cambio de rol de Cliente a un rol con MFA obligatorio: las sesiones se revocan y el usuario debe
  configurar MFA antes de operar con el nuevo rol.
- Cambio de rol o desactivación de un usuario con sesiones activas: las sesiones se revocan y la
  siguiente petición se evalúa con los permisos nuevos.
- Administrador que intenta reiniciar el MFA de otro usuario sin confirmar su propio código TOTP en
  ese momento, o con su propio MFA no activo: se rechaza.
- Atacante que provoca fallos sobre la cuenta de una víctima: el retraso es progresivo y acotado a
  15 minutos; la limitación por origen frena al atacante.
- Peticiones con identificadores de recurso secuenciales, aleatorios o mal formados: se deniegan o
  rechazan sin revelar la existencia del recurso.
- Fallo al registrar el evento de auditoría de una operación administrativa: la operación no se
  completa (falla de forma cerrada).
- Solicitudes de recuperación repetidas para la misma cuenta: cada nueva solicitud invalida los
  tokens anteriores y se aplica limitación de tasa.
- Buzón de laboratorio no disponible: la solicitud responde igual al usuario, el fallo de entrega se
  registra y no se escribe el token en ningún registro como alternativa.
- Usuario que intenta reutilizar la sesión de otro usuario o una sesión ya cerrada: se deniega.

## Requirements *(mandatory)*

### Functional Requirements

**Registro**

- **FR-001**: El sistema MUST permitir el autorregistro únicamente con el rol Cliente, solicitando
  solo identificador de correo, nombre y contraseña (minimización de datos).
- **FR-002**: El sistema MUST validar en el servidor todos los datos de registro (formato, longitud y
  campos permitidos) y rechazar cualquier campo no esperado, incluido el rol.
- **FR-003**: La política de contraseñas MUST aplicarse a todos los usuarios: longitud mínima de 15
  caracteres y máxima de 128, aceptación de cualquier carácter imprimible incluidos espacios y
  Unicode, y sin reglas de composición forzadas.
- **FR-004**: El sistema MUST rechazar contraseñas comunes, esperadas (que contengan el identificador,
  el nombre del usuario o el nombre del servicio) o comprometidas conocidas, mediante una lista de
  bloqueo.
- **FR-005**: El sistema MUST permitir el uso de gestores de contraseñas, el autocompletado y la
  acción de pegar en todos los campos de contraseña.
- **FR-006**: El sistema MUST impedir la existencia de dos cuentas con el mismo identificador.

**Credenciales y sesiones**

- **FR-007**: El sistema MUST almacenar las contraseñas exclusivamente como hash Argon2id con sal
  única por contraseña; ninguna contraseña puede almacenarse, mostrarse ni registrarse en texto
  plano ni con cifrado reversible.
- **FR-008**: El sistema MUST autenticar a los usuarios mediante identificador y contraseña y,
  cuando el usuario tenga MFA activo, además un código TOTP válido o un código de recuperación no
  usado.
- **FR-009**: El sistema MUST responder a cualquier fallo de autenticación (usuario inexistente,
  contraseña incorrecta, segundo factor inválido, cuenta en periodo de retraso o desactivada) con el
  mismo mensaje genérico.
- **FR-010**: El sistema MUST permitir al usuario cerrar sesión, revocando la sesión de forma que no
  pueda reutilizarse.
- **FR-011**: Las sesiones MUST expirar tras 15 minutos de inactividad y, en cualquier caso, tras
  8 horas desde su creación.
- **FR-012**: El sistema MUST revocar todas las sesiones de un usuario cuando cambie su contraseña,
  complete una recuperación de contraseña, se le reinicie el MFA o cambie su rol o el estado de su
  cuenta; y MUST revocar sus demás sesiones (conservando la actual) cuando él mismo active,
  desactive o reconfigure el MFA o regenere sus códigos de recuperación.
- **FR-013**: El mecanismo de sesión y sus controles CSRF/CORS asociados MUST elegirse y
  justificarse en la planificación técnica, conforme al Principio II de la constitución; esta
  especificación no lo fija.

**Roles y control de acceso**

- **FR-014**: El sistema MUST soportar tres roles predefinidos —Cliente, Administrador y Auditor—,
  con exactamente un rol por usuario.
- **FR-015**: Cada rol MUST tener asignado un conjunto fijo de permisos según la "Matriz de
  permisos"; cualquier función no asignada a un rol MUST denegarse (denegar por defecto).
- **FR-016**: El sistema MUST verificar en el servidor, en cada petición, la autenticación, el
  cumplimiento del requisito de MFA del rol, el permiso de función del rol y, para recursos de
  usuario, la propiedad del recurso (autorización a nivel de objeto).
- **FR-017**: Las denegaciones por falta de propiedad del recurso MUST responder sin revelar si el
  recurso existe.
- **FR-018**: El sistema MUST ignorar o rechazar cualquier intento de un usuario de modificar sus
  propios atributos privilegiados (rol, estado de la cuenta, estado de MFA) por vías distintas de las
  funciones autorizadas.

**Gestión administrativa**

- **FR-019**: Un Administrador MUST poder listar usuarios, crear cuentas de Administrador o Auditor,
  cambiar el rol de un usuario y desactivar o reactivar cuentas.
- **FR-020**: El sistema MUST impedir que un Administrador cambie su propio rol, desactive su propia
  cuenta o reinicie su propio MFA, y que se degrade o desactive al último Administrador activo.
- **FR-021**: Las cuentas creadas por un Administrador MUST activarse mediante un enlace de un solo
  uso entregado en el buzón de laboratorio, con caducidad de 24 horas y almacenado solo como hash,
  con el que el nuevo usuario establece su propia contraseña; el Administrador nunca conoce la
  contraseña. Los roles con MFA obligatorio MUST configurarlo antes de operar.
- **FR-022**: El primer Administrador MUST crearse únicamente mediante un procedimiento de
  inicialización ejecutado desde la consola del entorno controlado, sin credenciales
  predeterminadas y exigiendo la configuración de MFA en su primer acceso. MUST NOT existir ninguna
  interfaz pública (web o API) para crear administradores fuera de la función autenticada de
  FR-019.
- **FR-023**: La recuperación del último Administrador (pérdida de contraseña o de MFA sin otro
  Administrador disponible) MUST realizarse únicamente mediante un procedimiento extraordinario
  ejecutado desde la consola del entorno controlado, con las mismas garantías de FR-033 y FR-035, y
  quedar registrada; nunca mediante una interfaz pública.

**MFA (TOTP)**

- **FR-024**: Cualquier usuario MUST poder activar MFA TOTP confirmando un código válido antes de su
  activación; el secreto TOTP MUST mostrarse solo durante la configuración y almacenarse protegido,
  nunca en claro.
- **FR-025**: El requisito de MFA MUST ser un atributo del rol: opcional para Cliente y obligatorio
  para Administrador, Auditor y cualquier rol privilegiado que se añada en el futuro. Un usuario de
  un rol con MFA obligatorio sin MFA verificado MUST poder únicamente completar su configuración.
- **FR-026**: El sistema MUST rechazar códigos TOTP ya utilizados dentro de su ventana de validez y
  aceptar como máximo un intervalo de tolerancia por desfase de reloj.
- **FR-027**: Solo los usuarios de roles con MFA opcional MUST poder desactivarlo, confirmando
  contraseña y código válido.

**Códigos de recuperación de MFA**

- **FR-028**: Al activar el MFA, el sistema MUST generar 10 códigos de recuperación aleatorios
  criptográficamente seguros, mostrarlos una única vez y almacenar solo sus hashes.
- **FR-029**: Cada código de recuperación MUST poder sustituir al código TOTP en un único inicio de
  sesión y quedar invalidado tras su uso; el sistema MUST indicar al usuario cuántos le quedan.
- **FR-030**: El usuario MUST poder generar un nuevo conjunto de códigos, que invalida el anterior,
  solo tras confirmar su contraseña y un código TOTP válido.
- **FR-031**: Un usuario autenticado con un código de recuperación MUST poder reconfigurar su TOTP
  confirmando su contraseña y un código del nuevo dispositivo; la reconfiguración invalida el secreto
  y los códigos anteriores y genera un conjunto nuevo.

**Reinicio administrativo de MFA**

- **FR-032**: Un Administrador con MFA activo MUST poder reiniciar el MFA de otro usuario solo tras
  verificar su identidad mediante el procedimiento de verificación documentado, y confirmando su
  propio código TOTP en el momento del reinicio (reautenticación reforzada).
- **FR-033**: El reinicio MUST invalidar el secreto TOTP y todos los códigos de recuperación del
  usuario, revocar todas sus sesiones y exigir una nueva configuración de MFA en su siguiente acceso
  cuando su rol lo requiera.
- **FR-034**: El reinicio MUST registrar quién lo solicitó, quién lo autorizó, el método de
  verificación de identidad empleado y la fecha y hora, y MUST notificarse al usuario afectado en el
  buzón de laboratorio.
- **FR-035**: El reinicio MUST NOT conceder acceso, revelar ni modificar la contraseña del usuario;
  el Administrador MUST NOT ver en ningún caso el nuevo secreto ni los nuevos códigos.

**Protección frente a intentos repetidos**

- **FR-036**: A partir de 5 fallos consecutivos de autenticación sobre una cuenta (contraseña,
  código TOTP o código de recuperación), el sistema MUST aplicar retrasos progresivos crecientes
  entre intentos, con un enfriamiento máximo de 15 minutos; los intentos durante el retraso MUST
  rechazarse sin evaluar credenciales. El contador MUST reiniciarse tras una autenticación correcta.
- **FR-037**: El sistema MUST limitar además los intentos por origen (dirección IP) en la
  autenticación, el segundo factor, el registro, la recuperación y la activación de cuentas, con
  umbrales definidos en la planificación técnica.
- **FR-038**: El sistema MUST NOT aplicar bloqueos rígidos o permanentes por intentos fallidos, y el
  comportamiento observable MUST ser el mismo para cuentas existentes e inexistentes.
- **FR-039**: El sistema MUST registrar como eventos anómalos la activación de retrasos por cuenta,
  la limitación por origen y los intentos fallidos sobre varias cuentas desde un mismo origen.

**Registro de eventos**

- **FR-040**: El sistema MUST registrar como mínimo: registro y activación de cuenta; inicio de
  sesión exitoso y fallido; cierre de sesión; retrasos y limitaciones aplicados; activación,
  desactivación, reconfiguración y reinicio administrativo de MFA; códigos TOTP rechazados; uso y
  regeneración de códigos de recuperación; solicitud y uso de recuperación de contraseña; fallos de
  entrega al buzón; cambio de contraseña; cambio de rol; creación, desactivación y reactivación de
  cuentas; ejecución de los procedimientos de consola; y accesos denegados por autorización.
- **FR-041**: Cada evento MUST incluir marca de tiempo, tipo, actor mediante identificador interno o
  seudonimizado, recurso afectado, resultado y, cuando sea necesario para la investigación, el
  origen de la petición.
- **FR-042**: Los eventos MUST NOT contener contraseñas, códigos TOTP, secretos TOTP, códigos de
  recuperación, tokens de recuperación o activación, identificadores de sesión ni tokens de acceso.
- **FR-043**: Solo el Auditor MUST poder consultar y filtrar el contenido de los eventos (por rango de
  fechas, tipo, resultado y usuario); el Administrador no accede a su contenido y ningún rol puede
  modificarlos ni eliminarlos desde la aplicación.
- **FR-044**: Si el evento de auditoría de una operación administrativa no puede registrarse, la
  operación MUST NOT completarse.

**Recuperación de contraseña y canal de correo de laboratorio**

- **FR-045**: El sistema MUST permitir solicitar la recuperación de contraseña dando una respuesta
  idéntica exista o no la cuenta.
- **FR-046**: El token de recuperación MUST ser aleatorio e impredecible, de un solo uso, caducar a
  los 15 minutos, invalidar los tokens anteriores de la misma cuenta al emitirse uno nuevo,
  almacenarse solo como hash y no escribirse nunca en los registros de la aplicación.
- **FR-047**: Los correos del sistema (recuperación, activación y notificación de reinicio de MFA)
  MUST entregarse exclusivamente en un buzón de correo de laboratorio local que los captura; los
  correos MUST NOT enviarse a servicios externos. El buzón MUST ser accesible solo desde el entorno local
  autorizado, mantenerse separado de los registros de auditoría y usarse solo como infraestructura de
  laboratorio.
- **FR-048**: Completar la recuperación MUST cambiar la contraseña (cumpliendo FR-003 y FR-004),
  invalidar el token, revocar todas las sesiones y mantener el MFA si estaba activo.

**Documentación y verificación**

- **FR-049**: Cada mecanismo de seguridad de esta feature (hash de contraseñas, política de
  contraseñas, sesiones, RBAC, autorización a nivel de objeto, MFA, códigos de recuperación, reinicio
  administrativo de MFA, procedimientos de consola, protección frente a intentos repetidos, registro
  de eventos, recuperación de contraseña y buzón de laboratorio) MUST documentarse explicando cómo
  funciona, qué amenaza mitiga y por qué se eligió.
- **FR-050**: Cada requisito funcional MUST tener al menos una prueba positiva y, cuando proteja un
  control de seguridad, al menos una prueba negativa, ambas reproducibles.

### Matriz de permisos

| Función | Cliente | Administrador | Auditor |
|---|---|---|---|
| Requisito de MFA del rol | Opcional | Obligatorio | Obligatorio |
| Ver y editar el propio perfil (campos no privilegiados) | Sí | Sí | Sí |
| Cerrar la propia sesión | Sí | Sí | Sí |
| Configurar o reconfigurar el propio MFA | Sí | Sí | Sí |
| Desactivar el propio MFA | Sí | No | No |
| Regenerar los propios códigos de recuperación | Sí (con MFA) | Sí | Sí |
| Listar usuarios | No | Sí | No |
| Crear cuentas de Administrador o Auditor | No | Sí | No |
| Cambiar roles; desactivar o reactivar cuentas | No | Sí (no sobre sí mismo) | No |
| Reiniciar el MFA de otro usuario | No | Sí (no sobre sí mismo) | No |
| Consultar y filtrar el contenido de los eventos de seguridad | No | No | Sí |
| Modificar o eliminar eventos de seguridad | No | No | No |
| Acceder a recursos de otro usuario | No | Solo vía funciones administrativas | No |
| Crear el primer Administrador o recuperar el último | No (solo consola del entorno controlado) | No (solo consola del entorno controlado) | No (solo consola del entorno controlado) |

### Non-Functional Requirements

- **NFR-001 (Confidencialidad en tránsito)**: toda comunicación que transporte credenciales, códigos,
  tokens o datos de usuario entre el cliente y la plataforma MUST viajar cifrada, conforme al
  Principio III de la constitución.
- **NFR-002 (Rendimiento)**: el 95 % de los inicios de sesión sin retrasos activos MUST completarse en
  menos de 2 segundos con hasta 20 usuarios concurrentes en el entorno de laboratorio.
- **NFR-003 (Resistencia a enumeración)**: las respuestas de inicio de sesión y recuperación MUST ser
  indistinguibles en contenido para cuentas existentes e inexistentes, y su diferencia media de
  tiempo de respuesta MUST ser inferior a 100 ms.
- **NFR-004 (Privacidad)**: la feature MUST operar solo con identidades ficticias y recolectar solo
  los datos indicados en FR-001.
- **NFR-005 (Mínimo privilegio y separación de funciones)**: los roles MUST NOT tener permisos fuera
  de la matriz de permisos; la administración de usuarios y la consulta de auditoría MUST corresponder a
  roles distintos.
- **NFR-006 (Integridad de auditoría)**: los eventos MUST protegerse contra modificación desde la
  aplicación.
- **NFR-007 (Usabilidad de errores)**: los mensajes de validación MUST indicar la regla incumplida
  sin exponer detalles internos; los de autenticación MUST ser genéricos.
- **NFR-008 (Reproducibilidad)**: todas las pruebas de la feature MUST poder ejecutarse de nuevo con
  datos ficticios precargados y producir el mismo resultado.
- **NFR-009 (Aislamiento del canal de laboratorio)**: el buzón de correo de laboratorio MUST NOT ser
  accesible desde fuera del entorno local autorizado ni reenviar correos al exterior.

### Security Constraints & Preliminary Threat Considerations (STRIDE)

Resumen preliminar para trazabilidad; el análisis STRIDE completo (activos, impacto, mitigación,
criterio de aceptación y prueba) MUST elaborarse en `plan.md` según el Principio I.

| STRIDE | Amenaza principal | Requisitos que mitigan | Criterio de aceptación |
|---|---|---|---|
| Spoofing | Robo o adivinación de credenciales; relleno de credenciales; uso de códigos de recuperación robados; ingeniería social en el reinicio de MFA | FR-003–FR-008, FR-024–FR-036 | Sin contraseña y segundo factor válidos (cuando aplique) no se obtiene sesión; ningún reinicio sin verificación de identidad y reautenticación del Administrador |
| Tampering | Manipulación de rol o atributos privilegiados en peticiones; alteración de tokens | FR-002, FR-018, FR-046 | Los campos privilegiados enviados por el usuario nunca se aplican; tokens alterados se rechazan |
| Repudiation | Negar una acción administrativa, un reinicio de MFA o un procedimiento de consola | FR-034, FR-040, FR-041, FR-044 | Toda acción listada genera un evento atribuible con solicitante y autorizador cuando aplique |
| Information Disclosure | Enumeración de cuentas; secretos o tokens en registros; BOLA/IDOR; exposición del buzón de laboratorio | FR-009, FR-017, FR-042, FR-045–FR-047, NFR-003, NFR-009 | Respuestas indistinguibles; 0 secretos o tokens en registros; tokens y códigos solo como hash; 0 accesos a recursos ajenos; buzón inaccesible desde fuera del entorno local |
| Denial of Service | Bloqueo malicioso de cuentas; hash de entradas enormes; abuso de recuperación | FR-003, FR-036–FR-038 | El retraso por cuenta nunca supera 15 minutos; entradas > 128 caracteres se rechazan; limitación por origen activa |
| Elevation of Privilege | Cliente que invoca funciones administrativas; autoescalado; creación pública de administradores; reinicio de MFA como vía para eludir controles | FR-014–FR-016, FR-020, FR-022, FR-023, FR-032, FR-035 | 100 % de invocaciones fuera de la matriz denegadas; sin credenciales predeterminadas ni interfaz pública para crear o recuperar administradores; el reinicio no concede acceso |

### Key Entities *(include if feature involves data)*

- **Usuario**: identidad ficticia; identificador de correo único, nombre, hash de contraseña, rol,
  estado (pendiente de activación, activo, desactivado), estado de MFA, fechas de creación y de
  último acceso.
- **Rol**: Cliente, Administrador o Auditor; agrupa un conjunto fijo de permisos y define si el MFA
  es opcional u obligatorio.
- **Permiso**: función del sistema que un rol puede ejecutar (ver matriz).
- **Sesión**: vínculo autenticado entre un usuario y un cliente; fecha de creación, última actividad,
  expiración y estado (activa o revocada).
- **Configuración MFA**: secreto TOTP (almacenado protegido, nunca en claro), estado de verificación
  y último intervalo de código usado.
- **Código de recuperación**: hash de un código de un solo uso, conjunto al que pertenece y estado
  (disponible, usado o invalidado).
- **Reinicio de MFA**: usuario afectado, solicitante, Administrador autorizador, método de
  verificación de identidad y fecha.
- **Estado de intentos de autenticación**: contador de fallos por cuenta y por origen, retraso
  vigente y fin del periodo de enfriamiento.
- **Token de un solo uso**: hash de un token de recuperación o de activación, usuario asociado,
  propósito, caducidad y estado (pendiente, usado o invalidado).
- **Evento de seguridad**: registro inmutable con marca de tiempo, tipo, actor, recurso, resultado y
  origen.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Un cliente nuevo completa el registro y su primer inicio de sesión en menos de 2
  minutos.
- **SC-002**: El 100 % de los intentos de acceso a recursos de otro usuario o a funciones no
  permitidas por el rol, ejecutados en las pruebas negativas, son denegados (0 accesos no
  autorizados exitosos).
- **SC-003**: La inspección de los datos almacenados y de todos los registros generados durante las
  pruebas encuentra 0 contraseñas, códigos de recuperación o tokens en texto plano, y 0 secretos TOTP
  sin proteger.
- **SC-004**: En una prueba automatizada de 100 intentos fallidos rápidos contra una cuenta, como
  máximo 5 se evalúan antes de que se aplique el primer retraso, el 100 % de los intentos realizados
  durante un retraso se rechazan sin evaluar y ningún retraso supera 15 minutos.
- **SC-005**: El 100 % de los accesos a funcionalidades protegidas por usuarios Administrador o
  Auditor en las pruebas exigen un segundo factor válido.
- **SC-006**: El 100 % de los tipos de evento de FR-040 aparecen en el registro de auditoría con
  todos los campos de FR-041 tras ejecutar las pruebas.
- **SC-007**: El 0 % de los tokens de recuperación o activación y de los códigos de recuperación
  usados, vencidos, sustituidos o alterados es aceptado.
- **SC-008**: El 100 % de los reinicios de MFA de las pruebas quedan registrados con solicitante,
  autorizador, método de verificación y fecha, y el 0 % de los intentos de reinicio sobre sí mismo o
  sin reautenticación del Administrador tiene éxito.
- **SC-009**: El 100 % de los correos generados en las pruebas se capturan en el buzón de laboratorio
  y 0 se entregan a destinos externos.
- **SC-010**: El 95 % de los inicios de sesión sin retrasos activos se completan en menos de 2
  segundos con 20 usuarios concurrentes en el laboratorio.
- **SC-011**: El 100 % de los mecanismos listados en FR-049 cuentan con documentación de cómo
  funcionan y por qué se usan, y el 100 % de los requisitos funcionales tienen pruebas reproducibles.

## Assumptions

- Todas las identidades son ficticias; los identificadores de correo no se verifican contra buzones
  reales.
- El autorregistro solo crea Clientes; las cuentas de Administrador y Auditor las crea un
  Administrador o, en el caso del primer Administrador, el procedimiento de inicialización.
- Los roles y sus permisos son fijos en esta feature; no se crean roles personalizados.
- Los "recursos propios" de esta feature son el perfil, las sesiones y la configuración de seguridad
  del usuario; las cuentas y transferencias financieras llegarán en features posteriores y
  reutilizarán este control de acceso.
- Las "configuraciones administrativas" se limitan a la gestión de usuarios, roles, estado de cuentas
  y reinicio de MFA; los parámetros de seguridad (umbrales, tiempos) se fijan en la configuración del
  sistema y no se editan desde la aplicación.
- El procedimiento de verificación de identidad previo al reinicio de MFA es un procedimiento
  documentado fuera de banda (en el laboratorio, con datos ficticios de verificación); su detalle se
  define en la planificación técnica.
- La progresión exacta de los retrasos y los umbrales por origen se fijan en la planificación
  técnica, respetando el umbral de 5 fallos y el máximo de 15 minutos.
- Se permiten varias sesiones simultáneas por usuario.
- La política de contraseñas sigue las recomendaciones de NIST SP 800-63B (longitud y listas de
  bloqueo en lugar de reglas de composición).
- El reloj del servidor está sincronizado, requisito para validar códigos TOTP.
- Decisión aprobada: el buzón de correo de laboratorio será Mailpit (captura local por SMTP). Como
  componente nuevo, su inclusión MUST justificarse en `plan.md` (Principio VIII), y el tráfico SMTP
  interno sin TLS, si se usa, MUST documentarse como excepción de red interna aislada (Principio
  III).

## Out of Scope

- Cuentas financieras, saldos, transferencias y cualquier integración con proveedores financieros
  reales.
- Inicio de sesión con proveedores externos (SSO, OAuth con terceros) y verificación de identidad
  real.
- Envío real de correos o mensajes SMS a destinos externos.
- Roles personalizados o permisos editables desde la aplicación.
- Eliminación definitiva de cuentas (solo desactivación).
- Microservicios o servicios de identidad externos.
- Decisiones de arquitectura interna de autenticación, que se toman en `/speckit-plan`.
