import importlib

from functions import password_resets, supervisors
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


def test_script_dev_mode_helper_uses_shared_allowed_values():
    assert is_dev_mode_enabled("true") is True
    assert is_dev_mode_enabled("1") is True
    assert is_dev_mode_enabled(" yes ") is True
    assert is_dev_mode_enabled("on") is False
    assert is_dev_mode_enabled(None) is False


def test_send_test_email_import_is_side_effect_free():
    module = importlib.import_module("scripts.send_test_email")

    assert hasattr(module, "main")


# Copyright (c) Liam Suorsa and Mika Suorsa
