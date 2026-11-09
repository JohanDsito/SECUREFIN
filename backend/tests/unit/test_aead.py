"""TS-U03 / TS-U04 (T067): cifrado AES-256-GCM de los secretos TOTP con AAD ligada al usuario (R5)."""

from __future__ import annotations

import uuid

import pytest

from apps.iam.crypto import aead

pytestmark = pytest.mark.unit

SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"  # 160 bits en base32 (ficticio)


def test_roundtrip():
    user_id = uuid.uuid4()
    enc = aead.encrypt_totp_secret(user_id, SECRET)
    assert aead.decrypt_totp_secret(user_id, enc.nonce, enc.ciphertext, enc.key_version) == SECRET


def test_aad_is_bound_to_user():
    assert aead.aad_for(uuid.UUID(int=1)) == b"securefin:totp:v1:00000000-0000-0000-0000-000000000001"


def test_ciphertext_moved_to_another_user_fails_authentication():
    owner, other = uuid.uuid4(), uuid.uuid4()
    enc = aead.encrypt_totp_secret(owner, SECRET)
    with pytest.raises(aead.DecryptionError):
        aead.decrypt_totp_secret(other, enc.nonce, enc.ciphertext, enc.key_version)


def test_fresh_12_byte_nonce_per_encryption():
    user_id = uuid.uuid4()
    first = aead.encrypt_totp_secret(user_id, SECRET)
    second = aead.encrypt_totp_secret(user_id, SECRET)
    assert len(first.nonce) == len(second.nonce) == 12
    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext


def test_ciphertext_never_contains_the_secret_and_carries_gcm_tag():
    enc = aead.encrypt_totp_secret(uuid.uuid4(), SECRET)
    assert SECRET.encode() not in enc.ciphertext
    assert len(enc.ciphertext) == len(SECRET) + 16  # etiqueta GCM de 128 bits


def test_tampering_is_detected():
    user_id = uuid.uuid4()
    enc = aead.encrypt_totp_secret(user_id, SECRET)
    tampered = bytes([enc.ciphertext[0] ^ 1]) + enc.ciphertext[1:]
    with pytest.raises(aead.DecryptionError):
        aead.decrypt_totp_secret(user_id, enc.nonce, tampered, enc.key_version)
    with pytest.raises(aead.DecryptionError):
        aead.decrypt_totp_secret(user_id, bytes(12), enc.ciphertext, enc.key_version)


def test_active_version_and_unknown_version():
    user_id = uuid.uuid4()
    enc = aead.encrypt_totp_secret(user_id, SECRET)
    assert enc.key_version == "v1"
    with pytest.raises(aead.DecryptionError):
        aead.decrypt_totp_secret(user_id, enc.nonce, enc.ciphertext, "v9")
