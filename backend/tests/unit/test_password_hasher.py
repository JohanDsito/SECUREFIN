"""TS-U01 (T018): Argon2id m=64 MiB, t=3, p=1 como único hasher."""

import pytest
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password

pytestmark = pytest.mark.unit


def test_only_one_hasher_configured():
    assert settings.PASSWORD_HASHERS == ["apps.iam.policies.hashers.SecureFinArgon2Hasher"]


def test_hash_format_and_parameters():
    encoded = make_password("una contraseña de prueba larga")
    # Django antepone el nombre del algoritmo: "argon2$argon2id$v=19$m=65536,t=3,p=1$..."
    assert encoded.startswith("argon2$argon2id$v=19$m=65536,t=3,p=1$")
    assert check_password("una contraseña de prueba larga", encoded)
    assert not check_password("otra contraseña distinta", encoded)
