"""Recursos propios /users/{user_id}/… (T063; contrato §3; FR-010, FR-017, FR-018).

Dos capas en el servidor, en este orden:

1. Función (BFLA): `IsFullyAuthenticated` + `HasRolePermission(required_permission)`; sin permiso → 403.
2. Objeto (BOLA): `resolve_owned_user` solo acepta el propio id o el alias `me`; cualquier otro
   identificador, exista o no, esté bien formado o no → 404 idéntico y evento `authz_denied`.

Todas las consultas se filtran por el usuario de la sesión, nunca por el identificador recibido.
"""

from __future__ import annotations

import uuid

from django.contrib.auth import logout
from django.db import transaction
from rest_framework import status
from rest_framework.exceptions import NotFound
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.audit.services import record_event
from apps.iam.api.permissions import HasRolePermission, IsFullyAuthenticated, resolve_owned_user
from apps.iam.api.serializers.users import ProfileSerializer, SecuritySerializer, SessionSerializer
from apps.iam.policies.matrix import MFA_SELF, PROFILE_SELF, SESSIONS_SELF
from apps.iam.services import session_admin
from apps.iam.sessions.middleware import client_ip


class OwnResourceView(APIView):
    """Base: exige `required_permission` (la matriz de T058 lo comprueba en todas las rutas)."""

    required_permission: str

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.permission_classes = [IsFullyAuthenticated, HasRolePermission(cls.required_permission)]


class ProfileView(OwnResourceView):
    required_permission = PROFILE_SELF

    def get(self, request, user_id):
        owner = resolve_owned_user(request, user_id)
        return Response(ProfileSerializer(owner).data)

    def patch(self, request, user_id):
        owner = resolve_owned_user(request, user_id)
        serializer = ProfileSerializer(owner, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class SessionListView(OwnResourceView):
    required_permission = SESSIONS_SELF

    def get(self, request, user_id):
        owner = resolve_owned_user(request, user_id)
        rows = session_admin.active_sessions(owner)
        current = getattr(request.session, "row", None)
        context = {"current_public_id": getattr(current, "public_id", None)}
        return Response(SessionSerializer(rows, many=True, context=context).data)


class SessionDetailView(OwnResourceView):
    required_permission = SESSIONS_SELF

    def delete(self, request, user_id, public_id):
        owner = resolve_owned_user(request, user_id)
        try:
            pid = uuid.UUID(public_id)
        except ValueError:
            pid = None
        current = getattr(request.session, "row", None)
        if pid is not None and current is not None and current.public_id == pid:
            # Revocar la sesión actual equivale a cerrar sesión: borra la fila y la cookie.
            with transaction.atomic():
                record_event(
                    "sessions_revoked",
                    "success",
                    actor=owner,
                    target_type="session",
                    target_id=pid,
                    source_ip=client_ip(request),
                    metadata={"reason": "user_revoked_session", "pre_auth": 0, "full": 1},
                )
                logout(request)
            return Response(status=status.HTTP_204_NO_CONTENT)
        if pid is None or not session_admin.revoke_one(owner, pid):
            # Ajena, inexistente o mal formada: misma respuesta (FR-017).
            record_event(
                "authz_denied",
                "denied",
                actor=owner,
                source_ip=client_ip(request),
                metadata={"path": request.path[:200], "method": request.method, "reason": "object"},
            )
            raise NotFound()
        return Response(status=status.HTTP_204_NO_CONTENT)


class SecurityView(OwnResourceView):
    required_permission = MFA_SELF

    def get(self, request, user_id):
        owner = resolve_owned_user(request, user_id)
        return Response(SecuritySerializer(owner).data)
