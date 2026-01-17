# Copyright (c) Liam Suorsa
import pytest
from functions import hash_value

@pytest.mark.parametrize('value', [f'value{i}' for i in range(200)])
def test_hash_value_deterministic(value):
    """Ensure hash_value returns consistent hash for the same input."""
    assert hash_value(value) == hash_value(value)
