# Procedimientos de consola del entorno controlado

**Requisitos**: FR-022, FR-023, FR-033, FR-035, FR-041, FR-049. **Contrato**: `contracts/iam-api.md` §7.
**Código**: `backend/apps/iam/services/console.py`, `backend/apps/iam/management/commands/`.
**Pruebas**: `tests/integration/test_admin_and_console.py` (TS-I14; incluye la vigencia de 24 h del
enlace, que el mailer real entregue todo lo que encolan los procedimientos y la ejecución sin TTY en
un proceso real) y los escenarios 8 y 9 de `tests/acceptance/test_us4_admin.py`.

## Principios

- **Sin interfaz pública.** Ningún procedimiento de esta página tiene una ruta HTTP. Se ejecutan con
  `manage.py` dentro del contenedor `backend` y solo desde la máquina que aloja el stack. El escenario 9
  de aceptación recorre todas las rutas registradas y comprueba que ninguna es de bootstrap ni de
  break-glass.
- **Sin secretos en argumentos ni en la salida.** Ningún comando acepta contraseñas. Ninguno imprime
  tokens, enlaces ni códigos: lo que necesita el usuario llega a su buzón de laboratorio por el
  outbox.
- **Atribución.** Los eventos de consola registran en `os_user` la identidad efectiva del proceso en
  su entorno de ejecución, y no tienen actor de la aplicación. Dentro del contenedor `backend` el
  proceso corre como el usuario `app` (Dockerfile, `USER app`), así que normalmente se verá `app`:
  **no identifica a la persona** que ejecutó el comando en el host. La atribución humana depende de
  los controles de acceso al host, de quién tiene permisos sobre Docker y de los registros del
  sistema (sesiones, historial, auditoría del host). No se acepta un `--operator` declarado por quien
  ejecuta el comando: sería un dato autodeclarado, no una autenticación.
- **Atomicidad.** El cambio y su evento se escriben en la misma transacción (FR-044).
- **Código de salida.** Si no se cumple una precondición, el comando no modifica nada y sale con un
  código distinto de 0.

Todos los ejemplos se ejecutan desde la raíz del repositorio, con el stack levantado:

```bash
docker compose -f infra/compose.yaml exec backend python manage.py <comando> [opciones]
```

## Bootstrap del primer Administrador (FR-022)

```bash
docker compose -f infra/compose.yaml exec backend \
  python manage.py iam_bootstrap_admin --email admin@lab.securefin.local --name "Admin Lab"
```

1. **Precondición**: no existe **ningún** Administrador, en ningún estado. Dos ejecuciones simultáneas
   se serializan con `pg_advisory_xact_lock` y solo una crea la cuenta.
2. Se crea el Administrador en `pending_activation` con contraseña inutilizable: no hay credenciales
   predeterminadas.
3. Se encola `account_activation`. El mailer genera el token **en el momento de la entrega** y envía
   `https://securefin.local/activate#token=…` al buzón de laboratorio. El enlace es de un solo uso y
   vale **24 h contadas desde la entrega del correo**, no desde la ejecución del comando. Cada
   reintento o reenvío emite un token nuevo e invalida el anterior.
4. Se registra `bootstrap_admin_executed` con `os_user`.
5. El nuevo Administrador abre el enlace, fija su contraseña y, en su primer login, **debe dar de
   alta el MFA** antes de operar.

Si ya existe un Administrador, el comando falla. Los siguientes Administradores se crean desde la API
autenticada (`POST /admin/users`).

> **Limitación operativa conocida (T140).** Si el Administrador de bootstrap no activa su cuenta
> antes de que caduque el enlace, o pierde el correo, **no existe todavía ningún procedimiento para
> reenviarle la activación**: el bootstrap ya no se ejecuta (existe un Administrador, aunque esté
> pendiente), break-glass exige una cuenta activa y el reenvío de la API requiere otro
> Administrador. Activa la cuenta en cuanto llegue el correo. Antes de producción debe implementarse
> un procedimiento seguro de recuperación del primer Administrador (T140).

## Break-glass: recuperación del último Administrador (FR-023)

Solo para cuando el último Administrador perdió su MFA y no queda **ningún otro Administrador activo
con MFA** que pueda hacer el reinicio administrativo. Si existe alguno, el comando falla: hay que
usar el procedimiento de `admin-and-mfa-reset.md`. Se permite aunque exista otro Administrador
activo que todavía no haya dado de alta su MFA: es exactamente la condición del contrato §7, que no
se endurece sin cambiar antes los requisitos.

```bash
docker compose -f infra/compose.yaml exec backend \
  python manage.py iam_break_glass --email admin@lab.securefin.local --reason "Pérdida del móvil y de los códigos"
```

1. **Comprobación previa**, antes de preguntar nada: el correo es de un Administrador activo, no hay
   otro Administrador activo con MFA y el motivo no está vacío (máximo 200 caracteres, sin
   caracteres de control).
2. **Confirmación interactiva**: hay que escribir `yes`. Con cualquier otra respuesta no se modifica
   nada. No existe opción para saltarse la confirmación. Sin entrada interactiva (sin TTY, como con
   `docker compose exec -T`, o con la entrada cerrada o vacía) el comando termina con un error claro,
   código 1 y sin traza, antes de modificar ningún dato.
3. **Efectos**, en una única transacción y con los Administradores activos bloqueados:
   - invalida el TOTP y los códigos de recuperación disponibles (FR-033);
   - revoca todas las sesiones;
   - cancela cualquier caso de reinicio abierto y registra uno `authorized` con
     `request_verification = console` y `verification_method = console:break_glass`;
   - registra `break_glass_executed` con `os_user` y el motivo.
4. **Garantías (FR-035)**: la contraseña no se modifica y no se crea ninguna sesión. Quien opera la
   consola no ve ningún secreto. El Administrador inicia sesión con su contraseña y vuelve a dar de
   alta el MFA.

> **Recuperación de contraseña: pendiente de US7 (T141).** Break-glass recupera hoy el acceso
> relacionado con el **MFA**, no la contraseña. El contrato §7 prevé encolar además la recuperación
> de contraseña, pero el mailer todavía no tiene *handler* para `password_reset` (llega con T113, junto
> con `/reset` y `POST /auth/password-reset/confirm`). Por eso break-glass **no encola** ese correo:
> acabaría en `failed`. Si el último Administrador perdió también su contraseña, este procedimiento
> no basta hasta que T141 reincorpore el encolado con un *handler* funcional y probado.

**Quién puede ejecutarlo.** Solo el responsable del entorno controlado, con acceso privilegiado al
host y a Docker. Es una operación **excepcional**: no tiene límite de frecuencia propio, porque
ejecutarla ya exige esos privilegios. El motivo queda en la auditoría: no debe contener datos
personales ni secretos.

**Intentos rechazados.** Un intento que no cumple las precondiciones o que no se confirma **no genera
ningún evento de auditoría de la aplicación** (el catálogo cerrado solo tiene `break_glass_executed`
para las ejecuciones). Su atribución y revisión dependen de los registros del host.

## Rotación de claves

| Clave | Procedimiento | Detalle |
|---|---|---|
| `SESSION_HMAC_KEYS` | Añadir `vN+1`, publicarla como activa, esperar ≤ 8 h y ejecutar `iam_rotate_session_key --retire vN` | `sessions.md` |
| `TOTP_ENCRYPTION_KEYS` | Añadir `vN+1` y ejecutar `iam_rotate_totp_key --to vN+1` (recifra todo en una transacción; si un dispositivo falla, no cambia ninguno) | `mfa.md` |
| `TOKEN_HMAC_KEYS`, `THROTTLE_HMAC_KEYS` | Añadir la versión nueva y retirarla de la lista cuando caduquen los tokens o contadores anteriores | `secrets.md` |

Los comandos de rotación solo imprimen recuentos.

## Purga de caducados

`iam_purge_expired` (sesiones, tokens, altas pendientes, casos de reinicio y mensajes del outbox
caducados) llega en la fase de Polish (T117, con sus pruebas en T138). Hasta entonces, los casos de reinicio caducados se
marcan `expired` de forma perezosa y no bloquean solicitudes nuevas.
