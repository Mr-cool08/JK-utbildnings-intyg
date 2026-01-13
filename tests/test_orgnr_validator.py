import pytest

import functions


def test_validate_orgnr_accepts_hyphen():
    assert functions.validate_orgnr("556016-0680") == "5569668337"


def test_validate_orgnr_strips_spaces():
    assert functions.validate_orgnr(" 5569668337 ") == "5569668337"


def test_validate_orgnr_rejects_invalid_length():
    with pytest.raises(ValueError):
        functions.validate_orgnr("1234567")


def test_validate_orgnr_rejects_bad_checksum():
    with pytest.raises(ValueError):
        functions.validate_orgnr("5560160681")
