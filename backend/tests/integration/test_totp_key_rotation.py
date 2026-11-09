"""T079 (R8): `iam_rotate_totp_key --to vN` recifra todos los secretos TOTP sin perder ninguno."""

from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

import pytest
from django.core.management import CommandError, call_command

from apps.core import keys
from apps.iam.models import TOTPDevice
from apps.iam.services import mfa
from tests.helpers import make_totp_device, totp_code

pytestmark = pytest.mark.integration


@pytest.fixture
def totp_key_v2(monkeypatch):
    v2 = Path(os.environ["SECUREFIN_SECRETS_DIR"]) / "totp_key_v2"
    v2.write_text(base64.b64encode(secrets.token_bytes(32)).decode())

    def activate():
        monkeypatch.setenv("TOTP_KEY_VERSIONS", "v2,v1")
        keys.reset_cache()

    yield activate
    monkeypatch.delenv("TOTP_KEY_VERSIONS", raising=False)
    v2.unlink(missing_ok=True)
    keys.reset_cache()


def test_rotation_reencrypts_every_device(make_user, totp_key_v2, capsys):
    users = [make_user() for _ in range(3)]
    secrets_by_user = {u.id: make_totp_device(u) for u in users}
    totp_key_v2()  # los dispositivos se crearon con v1; ahora v2 pasa a ser la activa
    before = {d.id: (bytes(d.nonce), bytes(d.secret_ciphertext)) for d in TOTPDevice.objects.all()}

    call_command("iam_rotate_totp_key", to="v2")

    assert "3" in capsys.readouterr().out
    for device in TOTPDevice.objects.all():
        assert device.key_version == "v2"
        assert (bytes(device.nonce), bytes(device.secret_ciphertext)) != before[device.id]
    for user in users:  # los códigos siguen funcionando con el secreto recifrado
        assert mfa.verify_totp(user, totp_code(secrets_by_user[user.id])) is True


def test_rotation_output_never_contains_secrets(make_user, totp_key_v2, capsys):
    user = make_user()
    secret = make_totp_device(user)
    totp_key_v2()
    call_command("iam_rotate_totp_key", to="v2")
    assert secret not in capsys.readouterr().out


def test_unknown_version_is_rejected(make_user):
    with pytest.raises(CommandError):
        call_command("iam_rotate_totp_key", to="v7")
