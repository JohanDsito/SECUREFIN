"""Configuración base de SecureFin Gateway (T004).

Decisiones: R2 y R13 (sesiones), R3 (CSRF sin CORS), R4 (Argon2id), R8 (claves), R12
(limitación), R14 (roles de PostgreSQL), R10 (Mailpit).
"""

from __future__ import annotations

import os
from pathlib import Path

from apps.core import keys

BASE_DIR = Path(__file__).resolve().parents[2]


def env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


def _read_password() -> str:
    """Contraseña de la base de datos desde un archivo de secreto del propio servicio (U1)."""
    path = env("DB_PASSWORD_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return env("DB_PASSWORD", "") or ""


# --- Claves y entorno ----------------------------------------------------------------------------
SECRET_KEY = keys.django_secret_key()
DEBUG = False
ALLOWED_HOSTS = [h.strip() for h in (env("ALLOWED_HOSTS", "securefin.local") or "").split(",") if h]
FRONTEND_BASE_URL = env("FRONTEND_BASE_URL", "https://securefin.local")

# --- Aplicaciones (sin django.contrib.admin ni django.contrib.sessions; R2, R14) ------------------
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "rest_framework",
    "apps.core",
    "apps.audit",
    "apps.iam",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "apps.core.middleware.RequestIdMiddleware",
    "apps.core.middleware.ApiNoStoreMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "apps.iam.sessions.middleware.SessionLifetimeMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
TEMPLATES: list = []

# --- Base de datos: credenciales por servicio (U1) -----------------------------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("DB_NAME", "securefin"),
        "USER": env("DB_USER", "securefin_app"),
        "PASSWORD": _read_password(),
        "HOST": env("DB_HOST", "db"),
        "PORT": env("DB_PORT", "5432"),
        "OPTIONS": {"options": "-c search_path=securefin,public"},
        "CONN_MAX_AGE": 60,
    }
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Identidad ----------------------------------------------------------------------------------
AUTH_USER_MODEL = "iam.User"
AUTHENTICATION_BACKENDS = ["apps.iam.auth_backend.SessionUserBackend"]
PASSWORD_HASHERS = ["apps.iam.policies.hashers.SecureFinArgon2Hasher"]  # único hasher (R4)
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 15}},
    {"NAME": "apps.iam.policies.password_validators.MaximumLengthValidator", "OPTIONS": {"max_length": 128}},
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
        "OPTIONS": {"user_attributes": ("email", "name")},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "apps.iam.policies.password_validators.ServiceTermsBlocklistValidator"},
]

# --- Sesiones (R2, R13; decisión C2 alternativa B) -------------------------------------------------
SESSION_ENGINE = "apps.iam.sessions.store"
SESSION_COOKIE_NAME = "__Host-sf_session"
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_PATH = "/"
SESSION_COOKIE_DOMAIN = None
SESSION_SAVE_EVERY_REQUEST = False  # la cookie solo se emite al crear o rotar la sesión
SESSION_EXPIRE_AT_BROWSER_CLOSE = True  # cookie sin Expires
SESSION_COOKIE_AGE = 28800  # solo como tope absoluto (8 h)

SECUREFIN_SESSION = {
    "IDLE_TIMEOUT": 15 * 60,
    "ABSOLUTE_LIFETIME": 8 * 60 * 60,
    "PRE_AUTH_TTL": 5 * 60,
    "PRE_AUTH_ENROLL_TTL": 10 * 60,
    "TOUCH_GRANULARITY": 60,
}

# --- CSRF sin CORS (R3) ---------------------------------------------------------------------------
CSRF_COOKIE_NAME = "__Host-sf_csrftoken"
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = False  # el SPA debe leerla para enviar X-CSRFToken; no es una credencial
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_PATH = "/"
CSRF_USE_SESSIONS = False
CSRF_TRUSTED_ORIGINS = [env("CSRF_TRUSTED_ORIGIN", "https://securefin.local")]
CSRF_FAILURE_VIEW = "apps.iam.api.views.csrf.csrf_failure"

# --- Proxy y cabeceras ----------------------------------------------------------------------------
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "no-referrer"
X_FRAME_OPTIONS = "DENY"

# --- Caché en base de datos para la limitación por IP, sin Redis (R12) ---------------------------
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "securefin_cache",
    }
}

# --- Correo: solo el buzón de laboratorio, a través del proceso mailer (R9, R10) ------------------
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = env("EMAIL_HOST", "mailpit")
EMAIL_PORT = int(env("EMAIL_PORT", "1025") or 1025)
EMAIL_USE_TLS = False  # excepción E3: red interna aislada
EMAIL_USE_SSL = False
EMAIL_TIMEOUT = 3
DEFAULT_FROM_EMAIL = "SecureFin Lab <no-reply@lab.securefin.local>"

# --- Django REST Framework ------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["apps.iam.api.authentication.SecureSessionAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["apps.iam.api.permissions.IsFullyAuthenticated"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "EXCEPTION_HANDLER": "apps.iam.api.exceptions.exception_handler",
    "NUM_PROXIES": 1,
    # Limitación por IP (T101; R12). Solo actúa en las vistas que declaran `throttle_scope`.
    "DEFAULT_THROTTLE_CLASSES": ["apps.iam.api.throttles.IpScopedRateThrottle"],
    "DEFAULT_THROTTLE_RATES": {
        "login": "20/min",
        "mfa": "10/min",
        "register": "5/hour",
        "recovery": "5/hour",
        "activation": "10/hour",
        "mfa_reset_request": "3/day",
    },
    "UNAUTHENTICATED_USER": "django.contrib.auth.models.AnonymousUser",
}

# --- Internacionalización -------------------------------------------------------------------------
LANGUAGE_CODE = "es"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# --- Logs técnicos en JSON con redacción (R14) -----------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"redact": {"()": "apps.core.logging.RedactionFilter"}},
    "formatters": {"json": {"()": "apps.core.logging.JsonFormatter"}},
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "json", "filters": ["redact"]},
    },
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {
        "django.request": {"handlers": ["console"], "level": "WARNING", "propagate": False},
        "django.security": {"handlers": ["console"], "level": "WARNING", "propagate": False},
    },
}
