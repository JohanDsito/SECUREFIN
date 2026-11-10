"""Vistas de administración /admin/… (T090; contrato §4; FR-019, FR-020, FR-032–FR-035, FR-044).

Capas en el servidor, en este orden:

1. Sesión `full` con el MFA del rol cumplido (`IsFullyAuthenticated`): sin ella → 401.
2. Función (BFLA): `HasRolePermission(required_permission)`; solo el Administrador la tiene → 403 y
   evento `authz_denied` para Cliente y Auditor.
3. Reglas de negocio en los servicios (autooperación → 403, último Administrador o estado
   incompatible → 409), cada una con su evento en la misma transacción (FR-044).

Los identificadores llegan como `str` y se validan en el servicio: mal formado o inexistente → 404
idéntico. Las vistas no tocan el ORM (regla Semgrep `securefin-views-use-services`).
"""

from __future__ import annotations

import functools

from rest_framework import status
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.audit.services import record_event
from apps.iam.api.exceptions import BusinessRuleConflict, VerificationFailedError
from apps.iam.api.permissions import HasRolePermission, IsFullyAuthenticated
from apps.iam.api.serializers.admin import (
    AdminUserItemSerializer,
    AuthorizeCaseSerializer,
    ChangeRoleSerializer,
    CreatePrivilegedUserSerializer,
    MfaResetItemSerializer,
    MfaResetListQuerySerializer,
    OpenCaseSerializer,
    UserListQuerySerializer,
)
from apps.iam.api.serializers.mfa import EmptySerializer
from apps.iam.policies.matrix import (
    MFA_RESET_OTHERS,
    USERS_CREATE_PRIVILEGED,
    USERS_LIST,
    USERS_MANAGE,
    has_permission,
)
from apps.iam.services import admin_users, mfa_reset
from apps.iam.sessions.middleware import client_ip


class AdminView(APIView):
    """Base: la subclase declara `required_permission` (la matriz T058 lo comprueba en cada ruta)."""

    required_permission: str

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.permission_classes = [IsFullyAuthenticated, HasRolePermission(cls.required_permission)]


def _validated(serializer_class, data) -> dict:
    serializer = serializer_class(data=data)
    serializer.is_valid(raise_exception=True)
    return serializer.validated_data


def _require(request, permission: str) -> None:
    """Permiso adicional de un método concreto (misma semántica que HasRolePermission)."""
    if not has_permission(request.user.role, permission):
        record_event(
            "authz_denied",
            "denied",
            actor=request.user,
            source_ip=client_ip(request),
            metadata={"path": request.path[:200], "method": request.method, "reason": "function"},
        )
        raise PermissionDenied()


def _self_denied(request) -> PermissionDenied:
    record_event(
        "authz_denied",
        "denied",
        actor=request.user,
        source_ip=client_ip(request),
        metadata={"path": request.path[:200], "method": request.method, "reason": "self_action"},
    )
    return PermissionDenied(code="self_action_forbidden")


def _admin_errors(func):
    """Traduce los errores de los servicios a respuestas del contrato §4."""

    @functools.wraps(func)
    def wrapper(self, request, *args, **kwargs):
        try:
            return func(self, request, *args, **kwargs)
        except (admin_users.UserNotFoundError, mfa_reset.CaseNotFoundError) as exc:
            raise NotFound() from exc
        except (admin_users.SelfOperationError, mfa_reset.SelfOperationError) as exc:
            raise _self_denied(request) from exc
        except mfa_reset.WrongAdminError as exc:
            raise PermissionDenied(code="not_case_owner") from exc
        except (mfa_reset.MfaNotEnabledError, admin_users.ActorNotAdminError) as exc:
            raise PermissionDenied() from exc
        except admin_users.LastAdminError as exc:
            raise BusinessRuleConflict("No se puede degradar ni desactivar al último Administrador activo.", code="last_admin") from exc
        except admin_users.InvalidStatusError as exc:
            raise BusinessRuleConflict("El estado actual de la cuenta no permite esta operación.", code="invalid_state") from exc
        except admin_users.UserAlreadyExistsError as exc:
            raise BusinessRuleConflict("Ya existe una cuenta con ese correo.", code="user_exists") from exc
        except admin_users.InvalidRoleError as exc:
            raise ValidationError({"role": ["Rol no permitido."]}) from exc
        except mfa_reset.CaseConflictError as exc:
            raise BusinessRuleConflict("El caso ha caducado o ya está resuelto.", code="case_conflict") from exc
        except mfa_reset.VerificationFailedError as exc:
            raise VerificationFailedError("No se pudo verificar el código o el TOTP.") from exc

    return wrapper


def _page_number(page, has: bool, attr: str):
    return getattr(page, attr)() if has else None


# --- Usuarios ---------------------------------------------------------------------------------------
class AdminUsersView(AdminView):
    """GET /admin/users (listar) y POST /admin/users (crear Administrador o Auditor)."""

    required_permission = USERS_LIST

    def get(self, request):
        query = _validated(UserListQuerySerializer, request.query_params)
        page = admin_users.list_users(query.get("role"), query.get("status"), query["page"])
        return Response(
            {
                "results": AdminUserItemSerializer(page.object_list, many=True).data,
                "next": _page_number(page, page.has_next(), "next_page_number"),
                "previous": _page_number(page, page.has_previous(), "previous_page_number"),
            }
        )

    @_admin_errors
    def post(self, request):
        _require(request, USERS_CREATE_PRIVILEGED)
        data = _validated(CreatePrivilegedUserSerializer, request.data)
        user = admin_users.create_privileged_user(
            request.user, data["email"], data["name"], data["role"], source_ip=client_ip(request)
        )
        return Response({"id": str(user.id), "status": user.status}, status=status.HTTP_201_CREATED)


class ResendActivationView(AdminView):
    required_permission = USERS_MANAGE

    @_admin_errors
    def post(self, request, user_id):
        _validated(EmptySerializer, request.data)
        target = admin_users.get_user(user_id)
        admin_users.resend_activation(request.user, target)
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserRoleView(AdminView):
    required_permission = USERS_MANAGE

    @_admin_errors
    def patch(self, request, user_id):
        data = _validated(ChangeRoleSerializer, request.data)
        target = admin_users.get_user(user_id)
        user = admin_users.change_role(request.user, target, data["role"], source_ip=client_ip(request))
        return Response({"id": str(user.id), "role": user.role, "status": user.status})


class DeactivateUserView(AdminView):
    required_permission = USERS_MANAGE

    @_admin_errors
    def post(self, request, user_id):
        _validated(EmptySerializer, request.data)
        target = admin_users.get_user(user_id)
        admin_users.deactivate(request.user, target, source_ip=client_ip(request))
        return Response(status=status.HTTP_204_NO_CONTENT)


class ReactivateUserView(AdminView):
    required_permission = USERS_MANAGE

    @_admin_errors
    def post(self, request, user_id):
        _validated(EmptySerializer, request.data)
        target = admin_users.get_user(user_id)
        admin_users.reactivate(request.user, target, source_ip=client_ip(request))
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- Reinicio de MFA --------------------------------------------------------------------------------
class MfaResetListView(AdminView):
    required_permission = MFA_RESET_OTHERS

    def get(self, request):
        query = _validated(MfaResetListQuerySerializer, request.query_params)
        cases = mfa_reset.list_cases(query.get("status"))
        return Response({"results": MfaResetItemSerializer(cases, many=True).data})


class MfaResetOpenView(AdminView):
    required_permission = MFA_RESET_OTHERS

    @_admin_errors
    def post(self, request, case_id):
        data = _validated(OpenCaseSerializer, request.data)
        case = mfa_reset.open_case(request.user, case_id, data["request_channel"], source_ip=client_ip(request))
        return Response({"status": case.status})


class MfaResetAuthorizeView(AdminView):
    required_permission = MFA_RESET_OTHERS

    @_admin_errors
    def post(self, request, case_id):
        data = _validated(AuthorizeCaseSerializer, request.data)
        case = mfa_reset.authorize(
            request.user,
            case_id,
            verification_code=data["verification_code"],
            admin_totp_code=data["admin_totp_code"],
            channel_confirmed=data["channel_confirmed"],
            source_ip=client_ip(request),
        )
        return Response({"status": case.status})


class MfaResetCancelView(AdminView):
    required_permission = MFA_RESET_OTHERS

    @_admin_errors
    def post(self, request, case_id):
        _validated(EmptySerializer, request.data)
        mfa_reset.cancel(request.user, case_id, source_ip=client_ip(request))
        return Response(status=status.HTTP_204_NO_CONTENT)
