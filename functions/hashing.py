from __future__ import annotations

import hashlib
import logging
import os
import re
from functools import lru_cache

from werkzeug.security import check_password_hash, generate_password_hash

from config_loader import load_environment
from functions.logging import configure_module_logger


logger = configure_module_logger(__name__)
logger.setLevel(logging.DEBUG)

load_environment()

SALT = os.getenv("HASH_SALT", "static_salt")
if SALT == "static_salt":
    logger.warning(
        "Using default HASH_SALT; set HASH_SALT in environment for stronger security"
    )

DEFAULT_HASH_ITERATIONS = int(os.getenv("HASH_ITERATIONS", "200000"))
TEST_HASH_ITERATIONS = int(os.getenv("HASH_ITERATIONS_TEST", "1000"))


def _pbkdf2_iterations() -> int:
    # Return the iteration count for PBKDF2 operations.
    if os.getenv("PYTEST_CURRENT_TEST"):
        return TEST_HASH_ITERATIONS
    return DEFAULT_HASH_ITERATIONS


@lru_cache(maxsize=2048)
def _hash_value_cached(value: str, salt: str, iterations: int) -> str:
    # Cacheable helper for PBKDF2 hashing.
    return hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), iterations).hex()


def hash_value(value: str) -> str:
    # Return a strong deterministic hash of ``value`` using PBKDF2.
    iterations = _pbkdf2_iterations()
    logger.debug("Hashing value with %s iterations", iterations)
    return _hash_value_cached(value, SALT, iterations)


def normalize_email(email: str) -> str:
    # Normalize e-mail addresses before hashing or sending messages.
    if email is None:
        raise ValueError(
            "E-postadress saknas. Lägg till en adress så vi kan återkoppla till dig."
        )

    if "\n" in email or "\r" in email:
        raise ValueError(
            "Ogiltig e-postadress: adressen får inte innehålla radbrytningar."
        )

    cleaned = email.strip()

    if not cleaned:
        raise ValueError(
            "Ogiltig e-postadress: fyll i adressen enligt formatet namn@example.com."
        )

    if "@" not in cleaned or cleaned.startswith("@") or cleaned.endswith("@"):
        raise ValueError(
            "Ogiltig e-postadress: ange en adress med @ och domän, till exempel namn@example.com."
        )

    local_part, _, domain_part = cleaned.partition("@")
    if not local_part or "." not in domain_part or domain_part.startswith("."):
        raise ValueError(
            "Ogiltig e-postadress: kontrollera stavningen och inkludera domännamn, till exempel namn@example.com."
        )

    normalized = cleaned.lower()
    logger.debug("Normalizing email address")
    return normalized


def hash_password(password: str) -> str:
    # Hash a password with Werkzeug's PBKDF2 implementation.
    return generate_password_hash(password)


def verify_password(hashed: str, password: str) -> bool:
    # Verify a password against its hashed representation.
    return check_password_hash(hashed, password)


def normalize_personnummer(pnr: str) -> str:
    # Normalize Swedish personal numbers to the YYMMDDXXXX format.
    logger.debug("Normalizing personnummer")
    digits = re.sub(r"\D", "", pnr)
    if len(digits) == 12:
        digits = digits[2:]
    if len(digits) != 10:
        logger.error("Misslyckad normalisering av personnummer: ogiltigt format")
        raise ValueError("Ogiltigt personnummerformat.")
    logger.debug("Personnummer normaliserat")
    return digits


def normalize_orgnr(orgnr: str) -> str:
    # Normalisera organisationsnummer till exakt tio siffror.
    if orgnr is None:
        raise ValueError("Organisationsnummer saknas.")

    digits = re.sub(r"\D", "", orgnr)
    if len(digits) != 10:
        raise ValueError(
            "Organisationsnumret måste bestå av exakt tio siffror, till exempel 5569668337."
        )
    return digits


def validate_orgnr(orgnr: str) -> str:
    # Validera ett svenskt organisationsnummer med Luhn-mod10.
    normalized = normalize_orgnr(orgnr)
    total = 0
    for index, char in enumerate(normalized[:-1]):
        digit = int(char)
        if index % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    checksum = (10 - (total % 10)) % 10
    if checksum != int(normalized[-1]):
        raise ValueError(
            "Ogiltigt organisationsnummer. Kontrollera siffrorna och försök igen."
        )
    return normalized


def _hash_personnummer(pnr: str) -> str:
    # Normalize and hash a personal identity number.
    normalized = normalize_personnummer(pnr)
    return hash_value(normalized)


def _is_valid_hash(value: str) -> bool:
    # Verify that the hash is a 64-character hexadecimal string.
    if value is None:
        return False
    return bool(re.fullmatch(r"[a-f0-9]{64}", value))
