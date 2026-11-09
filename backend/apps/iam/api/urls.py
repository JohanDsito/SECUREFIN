"""Rutas de la API v1 (contrato §2–§5). Montadas en /api/v1/.

`user_id` y `public_id` usan el convertidor `str` (no `uuid`): así el alias `me` y los identificadores
mal formados llegan a la vista, que responde con el mismo 404 JSON y registra `authz_denied`, en
lugar de un 404 de enrutado distinto que revelaría qué identificadores son válidos (FR-017).
"""

from django.urls import path

from apps.iam.api.views.auth import LoginView, LogoutView, RegisterView, SessionView
from apps.iam.api.views.csrf import CsrfView
from apps.iam.api.views.users import ProfileView, SecurityView, SessionDetailView, SessionListView

urlpatterns = [
    path("auth/csrf", CsrfView.as_view(), name="auth-csrf"),
    path("auth/register", RegisterView.as_view(), name="auth-register"),
    path("auth/login", LoginView.as_view(), name="auth-login"),
    path("auth/logout", LogoutView.as_view(), name="auth-logout"),
    path("auth/session", SessionView.as_view(), name="auth-session"),
    # Recursos propios (contrato §3): Full + Owner
    path("users/<str:user_id>/profile", ProfileView.as_view(), name="user-profile"),
    path("users/<str:user_id>/sessions", SessionListView.as_view(), name="user-sessions"),
    path(
        "users/<str:user_id>/sessions/<str:public_id>",
        SessionDetailView.as_view(),
        name="user-session-detail",
    ),
    path("users/<str:user_id>/security", SecurityView.as_view(), name="user-security"),
]
