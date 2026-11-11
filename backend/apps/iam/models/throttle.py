"""Estado de la limitación progresiva por cuenta (T098; R12; data-model → AuthThrottle).

- El identificador nunca se guarda: solo `key_digest` = HMAC(THROTTLE_HMAC_KEYS[v],
  "throttle:acct:" + email normalizado), con su `key_version` para poder rotar la clave.
- Funciona igual para cuentas inexistentes (no hay clave foránea al usuario): un atacante no
  distingue por el comportamiento si el correo existe.
- `consecutive_failures` se reinicia tras un éxito o tras 30 min sin fallos.
- `blocked_until` = último fallo + 30 s · 2^(n−5), con tope de 900 s, desde n = 5.
"""

from __future__ import annotations

import uuid

from django.db import models


class ThrottleScope(models.TextChoices):
    ACCOUNT = "account", "Cuenta"


class AuthThrottle(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scope = models.CharField(max_length=16, choices=ThrottleScope.choices, default=ThrottleScope.ACCOUNT)
    key_digest = models.CharField(max_length=64)
    key_version = models.CharField(max_length=6)
    consecutive_failures = models.PositiveIntegerField(default=0)
    last_failure_at = models.DateTimeField()
    blocked_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "iam_auththrottle"
        constraints = [
            models.UniqueConstraint(fields=["scope", "key_digest"], name="iam_auththrottle_scope_digest_uniq"),
            models.CheckConstraint(
                condition=models.Q(scope__in=ThrottleScope.values), name="iam_auththrottle_scope_valid"
            ),
        ]
        indexes = [models.Index(fields=["key_version"], name="iam_auththrottle_version_idx")]

    def __str__(self) -> str:  # nunca muestra el resumen completo
        return f"AuthThrottle({self.scope}, {self.key_version}, fallos={self.consecutive_failures})"
