"""TS-U07 (T015): validación de claves al arrancar, una por propósito (C1) y rol del proceso (U1)."""

import base64
import os
import secrets

import pytest
from django.core.exceptions import ImproperlyConfigured

from apps.core import keys

pytestmark = pytest.mark.unit

FILES = ["django_secret_key", "session_hmac_key_v1", "token_hmac_key_v1", "throttle_hmac_key_v1", "totp_key_v1"]


@pytest.fixture
def secrets_dir(tmp_path, monkeypatch):
    for name in FILES:
        (tmp_path / name).write_text(base64.b64encode(secrets.token_bytes(32)).decode())
    monkeypatch.setenv("SECUREFIN_SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv("SECUREFIN_PROCESS_ROLE", "runtime")
    keys.reset_cache()
    yield tmp_path
    keys.reset_cache()


def _all_values(directory):
    return [(directory / n).read_text() for n in FILES]


def test_valid_keys_pass(secrets_dir):
    keys.validate_all(db_user="securefin_app")


@pytest.mark.parametrize("missing", FILES)
def test_missing_key_fails_closed(secrets_dir, missing):
    os.remove(secrets_dir / missing)
    with pytest.raises(ImproperlyConfigured, match="Falta"):
        keys.validate_all(db_user="securefin_app")


def test_short_key_fails(secrets_dir):
    (secrets_dir / "token_hmac_key_v1").write_text(base64.b64encode(b"x" * 16).decode())
    with pytest.raises(ImproperlyConfigured, match="menos de 32"):
        keys.validate_all(db_user="securefin_app")


@pytest.mark.parametrize("other", ["token_hmac_key_v1", "session_hmac_key_v1"])
def test_throttle_key_must_differ_from_other_hmac_keys(secrets_dir, other):
    (secrets_dir / "throttle_hmac_key_v1").write_text((secrets_dir / other).read_text())
    with pytest.raises(ImproperlyConfigured, match="Claves repetidas"):
        keys.validate_all(db_user="securefin_app")


def test_totp_key_must_be_exactly_32_bytes(secrets_dir):
    (secrets_dir / "totp_key_v1").write_text(base64.b64encode(secrets.token_bytes(48)).decode())
    with pytest.raises(ImproperlyConfigured, match="32 bytes"):
        keys.validate_all(db_user="securefin_app")


def test_runtime_process_cannot_use_owner_role(secrets_dir):
    with pytest.raises(ImproperlyConfigured, match="securefin_owner"):
        keys.validate_all(db_user="securefin_owner")


def test_migrate_process_may_use_owner_role(secrets_dir, monkeypatch):
    monkeypatch.setenv("SECUREFIN_PROCESS_ROLE", "migrate")
    keys.validate_all(db_user="securefin_owner")


def test_errors_never_reveal_key_values(secrets_dir):
    (secrets_dir / "throttle_hmac_key_v1").write_text((secrets_dir / "token_hmac_key_v1").read_text())
    with pytest.raises(ImproperlyConfigured) as excinfo:
        keys.validate_all(db_user="securefin_app")
    message = str(excinfo.value)
    for value in _all_values(secrets_dir):
        assert value not in message
