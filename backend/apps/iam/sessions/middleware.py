"""Segunda capa del ciclo de vida de la sesión (T035; R13; C2).

Se sitúa después de SessionMiddleware. Carga la sesión (lo que aplica en el motor la inactividad de
15 min y el límite absoluto de 8 h) y renueva ``last_activity_at`` con un UPDATE directo de
metadatos, sin modificar ``session_data`` ni reemitir la cookie.
"""

from __future__ import annotations

from apps.iam.sessions import keys as K


def client_ip(request) -> str | None:
    """IP real: Nginx sobrescribe X-Forwarded-For con $remote_addr (NUM_PROXIES = 1)."""
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[-1].strip() or None
    return request.META.get("REMOTE_ADDR")


class SessionLifetimeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        session = getattr(request, "session", None)
        if session is not None:
            session.client_meta = (client_ip(request), request.META.get("HTTP_USER_AGENT", ""))
            # Forzar la carga solo si el navegador envió una cookie de sesión.
            if session.session_key and session.get(K.LEVEL) in (K.PRE_AUTH, K.FULL):
                session.touch()
        return self.get_response(request)
