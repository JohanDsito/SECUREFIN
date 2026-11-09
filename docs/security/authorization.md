# Autorización: RBAC de función y de objeto, denegar por defecto

**Requisitos**: FR-013 a FR-018, FR-025, FR-049. **Decisiones**: research R1, R15. **Código**:
`backend/apps/iam/policies/matrix.py`, `backend/apps/iam/api/permissions.py` y
`backend/apps/iam/api/views/users.py`. **Pruebas**: `tests/security/test_authz_matrix.py` (TS-S01),
`tests/security/test_bola.py` (TS-S02), `tests/contract/test_users_contract.py` y
`tests/acceptance/test_us2_access_control.py`.

## Matriz de permisos

La matriz vive en **un único lugar**, `ROLE_PERMISSIONS` en `policies/matrix.py`. Las vistas, las
pruebas generadas y este documento derivan de ella.

| Permiso | Cliente | Administrador | Auditor | Rutas |
|---|:-:|:-:|:-:|---|
| `profile.self` | ✓ | ✓ | ✓ | `GET/PATCH /users/{id}/profile` |
| `sessions.self` | ✓ | ✓ | ✓ | `GET /users/{id}/sessions`, `DELETE /users/{id}/sessions/{public_id}` |
| `mfa.self` | ✓ | ✓ | ✓ | `GET /users/{id}/security`; altas y cambios de TOTP (US3) |
| `recovery_codes.self` | ✓ | ✓ | ✓ | Regenerar códigos de recuperación (US3) |
| `mfa.disable_self` | ✓ | — | — | Desactivar el propio MFA (US3); obligatorio para A y Au |
| `admin.users.list` / `.create_privileged` / `.manage` | — | ✓ | — | `/admin/users…` (US4) |
| `admin.mfa_reset` | — | ✓ | — | `/admin/mfa-resets…` (US4) |
| `audit.read` | — | — | ✓ | `/audit/…` (US6) |

Separación de funciones: el Administrador **no** lee la auditoría y el Auditor **no** administra.
El requisito de MFA es un atributo del rol (`ROLE_MFA_REQUIRED`); un rol desconocido lo exige por
defecto.

## Denegar por defecto

1. **Global**: `DEFAULT_PERMISSION_CLASSES = [IsFullyAuthenticated]`. Una vista nueva sin
   configuración exige una sesión `full`, usuario activo y el MFA de su rol cumplido. Sin eso → `401`.
2. **Anónimas, solo por lista**: las únicas vistas con `AllowAny` son las de `/auth/…` del contrato
   §2, y `test_route_inventory.py` falla si aparece otra.
3. **Función declarada**: toda vista protegida declara `required_permission` (la clase base
   `OwnResourceView` añade `HasRolePermission(required_permission)` automáticamente). La única
   excepción, `/auth/session`, figura en una lista explícita. `test_authz_matrix.py` recorre todas
   las rutas registradas y falla si una vista no declara su permiso o declara uno que no existe en la
   matriz, de modo que las rutas de US3–US7 quedan cubiertas sin tocar la prueba.
4. `has_permission(role, perm)` devuelve `False` para roles o permisos desconocidos.

## BFLA frente a BOLA

Son dos fallos distintos y se controlan en dos capas, en este orden:

| | BFLA (función) | BOLA / IDOR (objeto) |
|---|---|---|
| Pregunta | ¿Puede **este rol** invocar esta función? | ¿Es **este objeto** de este usuario? |
| Ejemplo de ataque | Un Cliente llama a `POST /admin/users` aunque la interfaz no lo muestre | El Cliente A pide `/users/{id_B}/profile` |
| Control | `HasRolePermission` (permiso DRF, antes de la vista) | `resolve_owned_user` y consultas filtradas por `request.user` |
| Respuesta | `403 forbidden` | `404 not_found` |
| Evento | `authz_denied` con `reason: "function"` | `authz_denied` con `reason: "object"` |

Como la capa de función se evalúa antes, un rol sin permiso recibe `403` aunque el identificador
sea ajeno.

### Cómo se evita BOLA

- `resolve_owned_user(request, user_id)` solo acepta el alias `me` o el `id` del usuario de la
  sesión. El identificador recibido **nunca** se usa para consultar: el servicio recibe el usuario de
  la sesión.
- Las sesiones se buscan con `filter(user=<usuario de la sesión>, public_id=…)`; una sesión ajena y
  una inexistente son indistinguibles.
- Las rutas usan el convertidor `str` (no `uuid`) para `user_id` y `public_id`. Así, un identificador
  mal formado llega a la vista y recibe el mismo `404` JSON y el mismo evento, en lugar de un `404`
  de enrutado con otro cuerpo que revelaría qué formatos son válidos.
- Los identificadores de usuario son UUID v4 y los de sesión, `public_id` UUID v4 distinto del
  verificador de la clave: no son secuenciales ni derivables.

## Respuesta 404 sin revelar existencia (FR-017)

Ante un recurso ajeno, inexistente o con identificador mal formado, la respuesta es **byte a byte
idéntica**: `404 {"error": {"code": "not_found", "message": "Recurso no encontrado."}}`. Un `403`
confirmaría que el recurso existe y que pertenece a otro usuario. `test_bola.py` compara los cuerpos
de un identificador real de B y de uno aleatorio, y prueba identificadores secuenciales, aleatorios y
mal formados.

La denegación se registra igualmente (`authz_denied`, con ruta, método y motivo, sin datos del
recurso), para que el Auditor pueda detectar barridos de identificadores.

## Asignación masiva (FR-018)

Los serializers usan **listas permitidas en ambos sentidos**. `StrictSerializer` rechaza con `400`
cualquier campo no declarado **o de solo lectura**: un `PATCH /users/me/profile` con `role`, `status`,
`email`, `mfa_enabled` o `mfa_required`, aunque vaya junto a un `name` válido, se rechaza entero y no
modifica nada. Rechazar en lugar de ignorar en silencio hace visible el intento al cliente y en las
pruebas. En la salida solo se exponen los campos del contrato: `SessionSerializer` publica
`public_id` y nunca el verificador.

## Por qué el frontend no es una frontera de confianza (FR-049)

El SPA oculta enlaces y botones según el rol, pero eso es **solo usabilidad**. Cualquier usuario
controla su navegador y puede llamar a la API directamente con `curl` o las herramientas de
desarrollo, manipular el JavaScript o cambiar identificadores en las URL. Por eso:

- toda decisión de autorización se toma en el servidor, en cada petición;
- el formulario de perfil solo envía `name`, pero la protección real es que el servidor rechaza el
  resto;
- las pruebas de autorización atacan la API, no la interfaz.

## Sustituto temporal en las pruebas

Hasta US3 no existe `TOTPDevice`, así que Administrador y Auditor no pueden obtener una sesión
`full`. La fixture `login_as` de `tests/conftest.py` da por cumplido el MFA **solo en las pruebas**,
para recorrer la matriz con los tres roles. Con US3 se sustituye por un alta TOTP real.
