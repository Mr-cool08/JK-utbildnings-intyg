import importlib

import app
import functions.security as security
from functions import password_resets, supervisors, users
from scripts import is_dev_mode_enabled


def test_password_reset_dev_mode_requires_exact_true(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    assert password_resets._dev_mode_enabled() is True

    monkeypatch.setenv("DEV_MODE", "yes")
    assert password_resets._dev_mode_enabled() is False


def test_supervisor_dev_mode_requires_exact_true(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    assert supervisors._dev_mode_enabled() is True

    monkeypatch.setenv("DEV_MODE", "1")
    assert supervisors._dev_mode_enabled() is False


def test_user_dev_mode_requires_exact_true(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    assert users._dev_mode_enabled() is True

    monkeypatch.setenv("DEV_MODE", "yes")
    assert users._dev_mode_enabled() is False


def test_script_dev_mode_helper_requires_exact_true():
    assert is_dev_mode_enabled("true") is True
    assert is_dev_mode_enabled("1") is False
    assert is_dev_mode_enabled(" yes ") is False
    assert is_dev_mode_enabled("on") is False
    assert is_dev_mode_enabled(None) is False


def test_extract_csrf_token_blocks_query_string_outside_dev_mode(monkeypatch):
    monkeypatch.setattr(security, "DEV_MODE", False)

    with app.app.test_request_context("/?csrf_token=test-token"):
        assert security.extract_csrf_token() is None


def test_validate_csrf_token_requires_dev_mode_for_missing_tokens(monkeypatch):
    monkeypatch.setattr(security, "DEV_MODE", False)
    with app.app.test_request_context("/"):
        assert security.validate_csrf_token(allow_if_absent=True) is False

    monkeypatch.setattr(security, "DEV_MODE", True)
    with app.app.test_request_context("/"):
        assert security.validate_csrf_token(allow_if_absent=True) is True


def test_send_test_email_import_is_side_effect_free():
    module = importlib.import_module("scripts.send_test_email")

    assert hasattr(module, "main")


# Copyright (c) Liam Suorsa and Mika Suorsa
