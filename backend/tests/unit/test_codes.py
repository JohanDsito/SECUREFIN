"""TS-U05 (T017): códigos de recuperación de 140 bits y códigos de verificación."""

import re

import pytest

from apps.iam.crypto import codes

pytestmark = pytest.mark.unit


def test_recovery_code_length_alphabet_and_entropy():
    code = codes.generate_recovery_code()
    assert len(code) == 28
    assert set(code) <= set(codes.CROCKFORD_ALPHABET)
    assert not set(code) & set("ILOU")
    assert codes.entropy_bits(len(code)) >= 128


def test_recovery_code_format_seven_groups_of_four():
    formatted = codes.format_code(codes.generate_recovery_code())
    assert re.fullmatch(r"([0-9A-Z]{4}-){6}[0-9A-Z]{4}", formatted)


def test_normalization_accepts_user_variants():
    code = codes.generate_recovery_code()
    messy = " " + codes.format_code(code).lower().replace("-", " - ") + " "
    assert codes.normalize_code(messy) == code
    assert codes.normalize_code("o0Il-1L") == "001111"  # O→0, I/L→1, sin guiones
    assert codes.normalize_code("ABC$") is None
    assert codes.normalize_code("") is None


def test_no_duplicates_in_100k_samples():
    sample = {codes.generate_recovery_code() for _ in range(100_000)}
    assert len(sample) == 100_000


def test_verification_code_is_8_crockford_chars():
    code = codes.generate_verification_code()
    assert len(code) == 8 and set(code) <= set(codes.CROCKFORD_ALPHABET)
