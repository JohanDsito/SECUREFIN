"""Autenticación DRF por sesión con respuesta 401 (contrato §1).

SessionAuthentication de DRF no define `authenticate_header`, y entonces DRF convierte los 401 en
403. Este subtipo declara un esquema para que "sin sesión" y "fallo de autenticación" respondan 401.
DRF sigue exigiendo CSRF a los usuarios autenticados.
"""

from rest_framework.authentication import SessionAuthentication


class SecureSessionAuthentication(SessionAuthentication):
    def authenticate_header(self, request):
        return 'Session realm="securefin"'
