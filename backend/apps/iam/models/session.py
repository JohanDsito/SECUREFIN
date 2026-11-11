"""Modelo de sesión que solo almacena verificadores HMAC (T033; R2; data-model → UserSession).

NO existe ningún campo `session_key`: si algún método heredado de Django intentara filtrar por
`session_key=`, el ORM lanzaría FieldError (falla de forma cerrada en lugar de consultar en claro).
"""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.db.models import F, Q, Value
from django.db.models.functions import Concat


class AuthLevel(models.TextChoices):
    PRE_AUTH = "pre_auth", "Pre-autenticación"
    FULL = "full", "Completa"


class UserSession(models.Model):
    key_verifier = models.CharField(max_length=72, primary_key=True)
    key_version = models.CharField(max_length=6, db_index=True)
    session_data = models.TextField()
    # Caducidad ABSOLUTA, nunca extendida: created_at + 8 h (full) o + 5/10 min (pre_auth)
    expire_date = models.DateTimeField(db_index=True)
    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    # Propietario en pre_auth (desde _sf_pending_user_id) y en full (desde _auth_user_id). Solo
    # correlaciona: revocación, expiración y eventos. No autentica ni otorga permisos (U3).
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="sessions",
        null=True,
        db_index=True,
    )
    auth_level = models.CharField(max_length=10, choices=AuthLevel.choices)
    created_at = models.DateTimeField()  # creación inicial; heredado en cada rotación (I3)
    authenticated_at = models.DateTimeField(null=True)  # informativo
    last_activity_at = models.DateTimeField()  # base de la inactividad de 15 min
    ip_address = models.GenericIPAddressField(null=True)
    user_agent = models.CharField(max_length=200, null=True)

    class Meta:
        db_table = "iam_usersession"
        indexes = [models.Index(fields=["user", "expire_date"], name="iam_session_user_exp_idx")]
        constraints = [
            models.CheckConstraint(
                condition=Q(key_verifier__startswith=Concat(F("key_version"), Value("$"))),
                name="iam_session_verifier_version_prefix",
            ),
            models.CheckConstraint(
                condition=Q(auth_level__in=[AuthLevel.PRE_AUTH, AuthLevel.FULL]),
                name="iam_session_auth_level_valid",
            ),
        ]

    def __str__(self) -> str:
        return f"UserSession({self.public_id})"
