"""Vistas anónimas que cambian estado: CSRF obligatorio (T041; R3).

DRF exime de CSRF a las peticiones anónimas; este decorador lo impone con `csrf_protect` sobre
`dispatch` para evitar el *login CSRF*, y declara explícitamente `AllowAny`.
"""

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from rest_framework.permissions import AllowAny


def anonymous_state_changing(view_cls):
    view_cls.permission_classes = [AllowAny]
    return method_decorator(csrf_protect, name="dispatch")(view_cls)
