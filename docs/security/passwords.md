# Contraseñas: Argon2id y política NIST

**Requisitos**: FR-003, FR-004, FR-005, FR-007, NFR-003. **Decisión**: research R4.
**Código**: `backend/apps/iam/policies/hashers.py`, `backend/apps/iam/policies/password_validators.py`,
`backend/apps/iam/services/authentication.py`.

## Cómo funciona

| Mecanismo | Implementación | Amenaza que mitiga |
|---|---|---|
| Hash Argon2id | Único hasher: `SecureFinArgon2Hasher` con m=64 MiB, t=3, p=1 y sal única por contraseña | Robo de la base de datos (ataques fuera de línea con GPU) |
| Longitud 15–128 | `MinimumLengthValidator(15)` y `MaximumLengthValidator(128)`; el serializer rechaza más de 128 **antes** de hashear | Contraseñas débiles; DoS con entradas enormes (T-21) |
| Lista de bloqueo | Lista integrada de Django (20 000 contraseñas comunes) + `blocklist.txt` local + términos del servicio | Contraseñas comunes, esperadas o comprometidas (FR-004) |
| Similitud con el usuario | `UserAttributeSimilarityValidator` sobre email y nombre | Contraseñas "esperadas" |
| Normalización NFKC | `normalize_password()` en el registro y en el login | Dos escrituras Unicode de la misma frase que no coinciden |
| Sin reglas de composición | No se exigen mayúsculas, dígitos ni símbolos (NIST SP 800-63B) | Contraseñas predecibles por reglas forzadas |
| Gestores de contraseñas | `autocomplete="new-password"` o `"current-password"`; se permite pegar | Contraseñas cortas o reutilizadas por fricción (FR-005) |
| Hash ficticio | Un identificador inexistente ejecuta Argon2id con los mismos parámetros | Enumeración por tiempo (NFR-003) |

## Por qué Argon2id

Argon2id es la recomendación actual de OWASP para el almacenamiento de contraseñas. Combina
resistencia a ataques con GPU y ASIC (por su coste de memoria) y a canales laterales. La
constitución (Principio III) lo reserva en exclusiva para contraseñas y para verificadores de
códigos de baja entropía.

El formato almacenado es el de Django:
`argon2$argon2id$v=19$m=65536,t=3,p=1$<sal>$<hash>`. El prefijo `argon2$` es el nombre del
algoritmo para Django.

## Calibración

Los parámetros iniciales se conservan. **No se reducen por rendimiento sin justificación escrita y
aprobación del titular**, y nunca por debajo del mínimo de OWASP (m=19 MiB, t=2, p=1). La
metodología (`python -m argon2` para el coste aislado y Apache Benchmark para la carga del endpoint)
y los resultados se registran en `argon2-calibration.md` (tareas T123 y T124).

## Verificación

TS-U01 (formato y parámetros), TS-U02 (validadores, incluido NFKC), TS-S22 (129 caracteres
rechazados sin hashear) y TS-S27 (enumeración por tiempo en el login).
