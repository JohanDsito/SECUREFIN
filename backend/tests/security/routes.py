"""Inventario de rutas de la API para las pruebas generadas (CSRF, matriz, inventario)."""

from __future__ import annotations

import re
import uuid

from django.urls import URLPattern, URLResolver, get_resolver

UNSAFE = ("post", "put", "patch", "delete")
_PARAM = re.compile(r"<(?:(?P<conv>\w+):)?(?P<name>\w+)>")


def _fill(route: str) -> str:
    def repl(match):
        name = match.group("name")
        return "me" if name == "user_id" else str(uuid.uuid4())

    return _PARAM.sub(repl, route)


def iter_api_routes():
    """Devuelve (ruta_concreta, clase_de_vista) para todas las rutas bajo /api/v1/."""

    def walk(patterns, prefix):
        for pattern in patterns:
            route = prefix + str(pattern.pattern)
            if isinstance(pattern, URLResolver):
                yield from walk(pattern.url_patterns, route)
            elif isinstance(pattern, URLPattern):
                view_class = getattr(pattern.callback, "view_class", None) or getattr(pattern.callback, "cls", None)
                if view_class is not None:
                    yield "/" + _fill(route), view_class

    yield from walk(get_resolver().url_patterns, "")


def unsafe_methods(view_class):
    return [m for m in UNSAFE if hasattr(view_class, m)]
