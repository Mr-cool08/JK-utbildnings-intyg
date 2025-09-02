import pytest
import functions


def test_normalize_personnummer_valid():
    assert functions.normalize_personnummer(" 19900101-1234 ") == "199001011234"
    assert functions.normalize_personnummer("900101-1234") == "199001011234"


def test_normalize_personnummer_invalid():
    with pytest.raises(ValueError):
        functions.normalize_personnummer("abc")
