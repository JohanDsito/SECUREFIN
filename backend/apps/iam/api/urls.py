"""Rutas de la API v1 (contrato §2–§5). Montadas en /api/v1/.

`user_id` y `public_id` usan el convertidor `str` (no `uuid`): así el alias `me` y los identificadores
mal formados llegan a la vista, que responde con el mismo 404 JSON y registra `authz_denied`, en
lugar de un 404 de enrutado distinto que revelaría qué identificadores son válidos (FR-017).
"""

from django.urls import path

from apps.iam.api.views.activation import ActivateView
from apps.iam.api.views.admin import (
    AdminUsersView,
    DeactivateUserView,
    MfaResetAuthorizeView,
    MfaResetCancelView,
    MfaResetListView,
    MfaResetOpenView,
    ReactivateUserView,
    ResendActivationView,
    UserRoleView,
)
from apps.iam.api.views.auth import LoginView, LogoutView, RegisterView, SessionView
from apps.iam.api.views.csrf import CsrfView
from apps.iam.api.views.mfa import (
    EnrollConfirmView,
    EnrollSetupView,
    LoginMfaView,
    MfaResetRequestView,
    RecoveryCodesRegenerateView,
    TotpConfirmView,
    TotpDisableView,
    TotpSetupView,
)
from apps.iam.api.views.users import ProfileView, SecurityView, SessionDetailView, SessionListView

urlpatterns = [
    path("auth/csrf", CsrfView.as_view(), name="auth-csrf"),
    path("auth/register", RegisterView.as_view(), name="auth-register"),
    path("auth/login", LoginView.as_view(), name="auth-login"),
    # Segundo paso del login (sesión pre_auth; contrato §2)
    path("auth/login/mfa", LoginMfaView.as_view(), name="auth-login-mfa"),
    path("auth/login/enroll/setup", EnrollSetupView.as_view(), name="auth-login-enroll-setup"),
    path("auth/login/enroll/confirm", EnrollConfirmView.as_view(), name="auth-login-enroll-confirm"),
    path("auth/login/mfa-reset-request", MfaResetRequestView.as_view(), name="auth-login-mfa-reset-request"),
    path("auth/logout", LogoutView.as_view(), name="auth-logout"),
    path("auth/session", SessionView.as_view(), name="auth-session"),
    path("auth/activate", ActivateView.as_view(), name="auth-activate"),
    # Recursos propios (contrato §3): Full + Owner
    path("users/<str:user_id>/profile", ProfileView.as_view(), name="user-profile"),
    path("users/<str:user_id>/sessions", SessionListView.as_view(), name="user-sessions"),
    path(
        "users/<str:user_id>/sessions/<str:public_id>",
        SessionDetailView.as_view(),
        name="user-session-detail",
    ),
    path("users/<str:user_id>/security", SecurityView.as_view(), name="user-security"),
    path("users/<str:user_id>/mfa/totp/setup", TotpSetupView.as_view(), name="user-mfa-totp-setup"),
    path("users/<str:user_id>/mfa/totp/confirm", TotpConfirmView.as_view(), name="user-mfa-totp-confirm"),
    path("users/<str:user_id>/mfa/totp/disable", TotpDisableView.as_view(), name="user-mfa-totp-disable"),
    path(
        "users/<str:user_id>/mfa/recovery-codes/regenerate",
        RecoveryCodesRegenerateView.as_view(),
        name="user-mfa-recovery-regenerate",
    ),
    # Administración (contrato §4): solo Administrador + Full
    path("admin/users", AdminUsersView.as_view(), name="admin-users"),
    path(
        "admin/users/<str:user_id>/activation/resend",
        ResendActivationView.as_view(),
        name="admin-user-activation-resend",
    ),
    path("admin/users/<str:user_id>/role", UserRoleView.as_view(), name="admin-user-role"),
    path("admin/users/<str:user_id>/deactivate", DeactivateUserView.as_view(), name="admin-user-deactivate"),
    path("admin/users/<str:user_id>/reactivate", ReactivateUserView.as_view(), name="admin-user-reactivate"),
    path("admin/mfa-resets", MfaResetListView.as_view(), name="admin-mfa-resets"),
    path("admin/mfa-resets/<str:case_id>/open", MfaResetOpenView.as_view(), name="admin-mfa-reset-open"),
    path(
        "admin/mfa-resets/<str:case_id>/authorize",
        MfaResetAuthorizeView.as_view(),
        name="admin-mfa-reset-authorize",
    ),
    path("admin/mfa-resets/<str:case_id>/cancel", MfaResetCancelView.as_view(), name="admin-mfa-reset-cancel"),
]
