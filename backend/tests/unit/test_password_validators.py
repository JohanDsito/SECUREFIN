"""TS-U02 (T046): política de contraseñas NIST (15–128, lista de bloqueo, NFKC, sin composición)."""

import pytest
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from apps.iam.models import User
from apps.iam.policies.password_validators import normalize_password

pytestmark = pytest.mark.unit

USER = User(email="ana.perez@lab.securefin.local", name="Ana Pérez Ficticia")


def _rejects(password, code=None):
    with pytest.raises(ValidationError) as excinfo:
        validate_password(password, user=USER)
    if code:
        assert code in [e.code for e in excinfo.value.error_list]


def test_rejects_14_characters():
    _rejects("abcdefghijklmn", "password_too_short")


def test_rejects_129_characters():
    _rejects("x" * 64 + "y" * 65, "password_too_long")


def test_rejects_common_password():
    _rejects("passwordpassword")


def test_rejects_service_terms():
    _rejects("securefin-gateway-2026", "password_service_term")
    _rejects("Mi Secure Fin favorita 99")


def test_rejects_expected_password_with_user_attributes():
    _rejects("ana.perez@lab.securefin.local", "password_too_similar")


def test_accepts_15_chars_with_spaces_and_unicode_without_composition_rules():
    validate_password("árbol nube río lago", user=USER)
    validate_password("solo minusculas sin numeros", user=USER)
    validate_password("123456789048213", user=USER)  # solo dígitos: NIST no impone composición


def test_nfkc_normalization_is_consistent():
    composed = "Café con leche y pan"
    decomposed = "Café con leche y pan"
    assert normalize_password(composed) == normalize_password(decomposed)
    fullwidth = "ＰＡＳＳＷＯＲＤ ancho completo"
    assert normalize_password(fullwidth).startswith("PASSWORD")
