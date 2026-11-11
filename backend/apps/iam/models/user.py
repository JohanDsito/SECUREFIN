"""Modelo de usuario (T031; data-model → User)."""

from __future__ import annotations

import unicodedata
import uuid

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.functions import Lower

from apps.core import clock


def validate_no_control_chars(value: str) -> None:
    if any(unicodedata.category(ch).startswith("C") for ch in value):
        raise ValidationError("El nombre no puede contener caracteres de control.")


class Role(models.TextChoices):
    CLIENT = "client", "Cliente"
    ADMIN = "admin", "Administrador"
    AUDITOR = "auditor", "Auditor"


class Status(models.TextChoices):
    PENDING_ACTIVATION = "pending_activation", "Pendiente de activación"
    ACTIVE = "active", "Activo"
    DEACTIVATED = "deactivated", "Desactivado"


class UserManager(BaseUserManager):
    use_in_migrations = True

    def normalize_email(self, email):  # siempre minúsculas (data-model)
        return (email or "").strip().lower()

    def create_user(self, email, name, password=None, role=Role.CLIENT, status=Status.ACTIVE):
        user = self.model(email=self.normalize_email(email), name=name, role=role, status=status)
        if password is None:
            user.set_unusable_password()
        else:
            user.set_password(password)
        user.full_clean(exclude=["password"])
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # unique + CHECK de minúsculas = unicidad sin distinguir mayúsculas (data-model)
    email = models.EmailField(max_length=254, unique=True)
    name = models.CharField(max_length=100, validators=[validate_no_control_chars])
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.CLIENT)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)
    created_at = models.DateTimeField(default=clock.default_now)
    last_login_at = models.DateTimeField(null=True, blank=True)
    password_changed_at = models.DateTimeField(null=True, blank=True)

    # Se desactiva el campo last_login de Django (y su señal): usamos last_login_at.
    last_login = None

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = ["name"]

    objects = UserManager()

    class Meta:
        db_table = "iam_user"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(email=Lower("email")), name="iam_user_email_lowercase"
            ),
        ]

    def save(self, *args, **kwargs):
        self.email = (self.email or "").strip().lower()
        super().save(*args, **kwargs)

    @property
    def is_active(self) -> bool:
        return self.status == Status.ACTIVE

    def __str__(self) -> str:  # nunca expone datos sensibles
        return f"User({self.id})"
