"""TS-U06 (T016): formato, separación de dominio y separación de claves (C1)."""

import base64
import re
import secrets
import shutil

import pytest

from apps.core import keys
from apps.iam.crypto import hmac_verifiers as hv

pytestmark = pytest.mark.unit


def test_session_verifier_format_and_length():
    verifier = hv.session_verifier("a" * 43)
    assert re.fullmatch(r"v\d{1,5}\$[0-9a-f]{64}", verifier)
    assert len(verifier) <= 72


def test_domain_separation_same_input():
    value = "mismo-valor@lab.securefin.local"
    session = hv.session_verifier(value).split("$", 1)[1]
    _, token = hv.token_verifier("password_reset", value)
    _, throttle = hv.throttle_digest(value)
    assert len({session, token, throttle}) == 3


def test_token_purpose_separation():
    token = secrets.token_urlsafe(32)
    _, activation = hv.token_verifier("account_activation", token)
    _, reset = hv.token_verifier("password_reset", token)
    assert activation != reset


def test_throttle_digest_normalizes_email():
    assert hv.throttle_digest(" Ana@Lab.SecureFin.local ") == hv.throttle_digest("ana@lab.securefin.local")


def test_verify_is_constant_time_compare():
    assert hv.verify("abc", "abc")
    assert not hv.verify("abc", "abd")


def test_changing_one_key_does_not_affect_other_purposes(tmp_path, monkeypatch):
    """Cada función usa SOLO su conjunto de claves: rotar la de limitación no altera las demás."""
    import os

    original = os.environ["SECUREFIN_SECRETS_DIR"]
    shutil.copytree(original, tmp_path, dirs_exist_ok=True)
    value = "persona@lab.securefin.local"
    before = (hv.session_verifier(value), hv.token_verifier("password_reset", value), hv.throttle_digest(value))
    (tmp_path / "throttle_hmac_key_v1").write_text(base64.b64encode(secrets.token_bytes(32)).decode())
    monkeypatch.setenv("SECUREFIN_SECRETS_DIR", str(tmp_path))
    keys.reset_cache()
    try:
        after = (hv.session_verifier(value), hv.token_verifier("password_reset", value), hv.throttle_digest(value))
    finally:
        monkeypatch.setenv("SECUREFIN_SECRETS_DIR", original)
        keys.reset_cache()
    assert before[0] == after[0]
    assert before[1] == after[1]
    assert before[2] != after[2]
