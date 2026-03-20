# Copyright (c) Liam Suorsa and Mika Suorsa
import os
import sys


sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import functions  # noqa: E402


def test_is_truthy_various_inputs():
    assert functions._is_truthy("  JA  ")
    assert functions._is_truthy("true")
    assert not functions._is_truthy("nej")
    assert not functions._is_truthy(None)


def test_clean_optional_text_trims_and_limits_length():
    assert functions._clean_optional_text(None) is None
    assert functions._clean_optional_text("   ") is None
    assert functions._clean_optional_text("  text  ") == "text"
    long_value = "x" * 50
    assert functions._clean_optional_text(long_value, max_length=10) == "x" * 10
