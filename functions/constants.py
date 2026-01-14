from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from config_loader import load_environment
from functions.logging.logging_utils import configure_module_logger


logger = configure_module_logger(__name__)
logger.setLevel(logging.DEBUG)

# --- SQLite shim for platforms without stdlib _sqlite3 ---
try:
    import pysqlite3 as sqlite3

    sys.modules["sqlite3"] = sqlite3
except Exception as exc:
    logger.warning(
        "Failed to import pysqlite3, falling back to stdlib sqlite3: %s", exc
    )


load_environment()

APP_ROOT = Path(__file__).resolve().parent.parent

SALT = os.getenv("HASH_SALT", "static_salt")
if SALT == "static_salt":
    logger.warning(
        "Using default HASH_SALT; set HASH_SALT in environment for stronger security"
    )

DEFAULT_HASH_ITERATIONS = int(os.getenv("HASH_ITERATIONS", "200000"))
TEST_HASH_ITERATIONS = int(os.getenv("HASH_ITERATIONS_TEST", "1000"))
