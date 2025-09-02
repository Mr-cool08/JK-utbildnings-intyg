"""Additional tests for hashing and personal number utilities."""

import os
import sys
import pytest

# Ensure the project root is on ``sys.path`` so ``functions`` can be imported
# when tests are executed directly.
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from functions import (
    hash_value,
    hash_password,
    verify_password,
    normalize_personnummer,
)


@pytest.mark.parametrize("value", [f"input{i}" for i in range(10)])
def test_hash_value_deterministic(value):
    """Hashing the same value twice should yield the same result."""
    assert hash_value(value) == hash_value(value)


@pytest.mark.parametrize("password", [f"pass{i}" for i in range(10)])
def test_hash_password_verify(password):
    """Passwords hashed with ``hash_password`` should verify correctly."""
    hashed = hash_password(password)
    assert verify_password(hashed, password)


@pytest.mark.parametrize("password", [f"pass{i}" for i in range(10)])
def test_verify_password_fails(password):
    """Verification should fail for incorrect passwords."""
    hashed = hash_password(password)
    assert not verify_password(hashed, password + "x")


valid_numbers = [f"199001{day:02d}-0000" for day in range(1, 11)]


@pytest.mark.parametrize("pnr", valid_numbers)
def test_normalize_personnummer_valid(pnr):
    """Valid personal numbers should normalize to 12 digits."""
    normalized = normalize_personnummer(pnr)
    assert len(normalized) == 12
    assert normalized.isdigit()


invalid_numbers = [
    "19900101",
    "",
    "abc",
    "19900101-000",
    "1990010100000",
    "990101-000",
    "1990010",
    "19900101000",
    "19900101-0000a1",
    "19900101000000",
]


@pytest.mark.parametrize("pnr", invalid_numbers)
def test_normalize_personnummer_invalid(pnr):
    """Invalid personal numbers should raise ``ValueError``."""
    with pytest.raises(ValueError):
        normalize_personnummer(pnr)
