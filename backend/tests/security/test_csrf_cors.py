"""TS-S05/S06/S07 (T023): CSRF en todas las rutas no seguras, sin CORS y con validación de origen.

La prueba recorre el resolver de URLs, así que crece sola con cada ruta nueva.
"""

import pytest

from tests.security.routes import iter_api_routes, unsafe_methods

pytestmark = pytest.mark.security


def _routes():
    return [(path, m) for path, cls in iter_api_routes() for m in unsafe_methods(cls)]


def _call(api, method, path, **kwargs):
    return getattr(api, method)(path[len("/api/v1"):], **kwargs) if method != "delete" else api.delete(path[len("/api/v1"):], **kwargs)


def test_there_are_unsafe_routes_to_check():
    assert _routes(), "el inventario debe encontrar rutas POST/PATCH/DELETE"


@pytest.mark.parametrize("path,method", _routes())
def test_anonymous_unsafe_request_without_token_is_rejected(api, db, path, method):
    api.fetch_csrf()
    kwargs = {"csrf": False} if method == "delete" else {"data": {}, "csrf": False}
    response = _call(api, method, path, **kwargs)
    assert response.status_code in (401, 403)
    assert response.status_code != 200


@pytest.mark.parametrize("path,method", _routes())
def test_authenticated_unsafe_request_without_token_is_403(api, make_user, path, method):
    api.login(make_user().email)
    kwargs = {"csrf": False} if method == "delete" else {"data": {}, "csrf": False}
    response = _call(api, method, path, **kwargs)
    assert response.status_code == 403


def test_foreign_origin_rejected_even_with_token(api, make_user):
    user = make_user()
    api.fetch_csrf()
    response = api.post("/auth/login", {"email": user.email, "password": "x" * 20},
                        HTTP_ORIGIN="https://evil.example")
    assert response.status_code == 403


@pytest.mark.parametrize("path,cls", list(iter_api_routes()))
def test_no_cors_headers_anywhere(api, db, path, cls):
    response = api.client.options(path, secure=True, HTTP_ORIGIN="https://evil.example",
                                  HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST")
    assert "Access-Control-Allow-Origin" not in response
    response = api.client.get(path, secure=True, HTTP_ORIGIN="https://evil.example")
    assert "Access-Control-Allow-Origin" not in response
