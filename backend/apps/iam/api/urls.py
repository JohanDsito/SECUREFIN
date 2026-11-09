"""Rutas de la API v1 (contrato §2–§5). Montadas en /api/v1/."""

from django.urls import path

from apps.iam.api.views.auth import LoginView, LogoutView, RegisterView, SessionView
from apps.iam.api.views.csrf import CsrfView

urlpatterns = [
    path("auth/csrf", CsrfView.as_view(), name="auth-csrf"),
    path("auth/register", RegisterView.as_view(), name="auth-register"),
    path("auth/login", LoginView.as_view(), name="auth-login"),
    path("auth/logout", LogoutView.as_view(), name="auth-logout"),
    path("auth/session", SessionView.as_view(), name="auth-session"),
]
