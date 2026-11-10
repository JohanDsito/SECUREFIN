"""Autorregistro de Clientes (T053; FR-001 a FR-006)."""

from __future__ import annotations

from django.contrib.auth.password_validation import validate_password
from django.db import IntegrityError, transaction

from apps.audit.services import record_event
from apps.finance.services.accounts import ensure_welcome_account
from apps.iam.models import Role, Status, User
from apps.iam.policies.password_validators import normalize_password


class RegistrationUnavailable(Exception):
    """Identificador no disponible. Se comunica con un mensaje neutro (riesgo residual en STRIDE)."""


def register(email: str, name: str, password: str, source_ip: str | None = None) -> User:
    email = (email or "").strip().lower()
    password = normalize_password(password)
    # El rol SIEMPRE es Cliente: el serializer ya rechaza cualquier campo `role` (FR-001, T-07).
    user = User(email=email, name=name.strip(), role=Role.CLIENT, status=Status.ACTIVE)
    validate_password(password, user=user)  # lanza ValidationError con la regla incumplida
    user.set_password(password)
    if User.objects.filter(email=email).exists():
        raise RegistrationUnavailable
    try:
        with transaction.atomic():
            user.save()
            ensure_welcome_account(user)
            record_event("account_registered", "success", actor=user, target_type="user",
                         target_id=user.id, source_ip=source_ip)
    except IntegrityError as exc:  # carrera con otro registro simultáneo
        raise RegistrationUnavailable from exc
    return user
