"""Hasher de contraseñas Argon2id (T032; R4; constitución, Principio III).

Parámetros iniciales m=64 MiB, t=3, p=1. NO se reducen por rendimiento sin justificación escrita y
aprobación del titular, y nunca por debajo del mínimo de OWASP (m=19 MiB, t=2, p=1). La
calibración se documenta en docs/security/argon2-calibration.md (T123, T124).
"""

from django.contrib.auth.hashers import Argon2PasswordHasher


class SecureFinArgon2Hasher(Argon2PasswordHasher):
    # Django guarda el resultado como "argon2$argon2id$v=19$m=65536,t=3,p=1$<sal>$<hash>"
    time_cost = 3
    memory_cost = 65536  # KiB = 64 MiB
    parallelism = 1
