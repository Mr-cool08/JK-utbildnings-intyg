# Copyright (c) Liam Suorsa
"""Omfattande tester för kurskategori-hjälpfunktioner."""

import pytest

from course_categories import labels_for_slugs, normalize_category_slugs


@pytest.mark.parametrize(
    "input_values, expected",
    [
        (["fallskydd"], ["fallskydd"]),
        (["FALLSKYDD"], ["fallskydd"]),
        ([" Lift "], ["lift"]),
        (["truck", "truck"], ["truck"]),
        (["heta-arbeten", "unknown"], ["heta-arbeten"]),
        (["unknown"], []),
        (["fallskydd", "lift"], ["fallskydd", "lift"]),
        (["lift", "fallskydd"], ["lift", "fallskydd"]),
        (["", " "], []),
        (["säKRA-Lyft"], ["säkra-lyft"]),
        (["Fallskydd", "fallskydd", "FALLSKYDD"], ["fallskydd"]),
        (["fallskydd", " lift "], ["fallskydd", "lift"]),
        ([" Heta-Arbeten "], ["heta-arbeten"]),
        (["truck", "Lift", "Säkra-Lyft"], ["truck", "lift", "säkra-lyft"]),
        (["lift", "Lift", "lift "], ["lift"]),
        (["säkrA-lyft", "TRUCK", "unknown"], ["säkra-lyft", "truck"]),
        (["FALLSKYDD", "lift", "Lift"], ["fallskydd", "lift"]),
        (["\tsäkra-lyft\n"], ["säkra-lyft"]),
        (["fallskydd", "unknown", " lift "], ["fallskydd", "lift"]),
        (
            ["TRUCK", "Fallskydd", "Lift", "HETA-ARBETEN"],
            ["truck", "fallskydd", "lift", "heta-arbeten"],
        ),
        (["lift", "säkra-lyft", "fallskydd", "lift"], ["lift", "säkra-lyft", "fallskydd"]),
        (["truck", "   ", "heta-arbeten"], ["truck", "heta-arbeten"]),
        (["lift", "Lift", "LIFT", "lift"], ["lift"]),
        (
            [" fallskydd ", " säkra-lyft ", "unknown", "truck"],
            ["fallskydd", "säkra-lyft", "truck"],
        ),
        (["HETA-ARBETEN", " SäKrA-LyFt "], ["heta-arbeten", "säkra-lyft"]),
    ],
)
def test_normalize_category_slugs(input_values, expected):
    assert normalize_category_slugs(input_values) == expected


@pytest.mark.parametrize(
    "slugs, expected_labels",
    [
        (["fallskydd"], ["Fallskydd"]),
        (["lift"], ["Lift"]),
        (["säkra-lyft"], ["Säkra lyft"]),
        (["truck"], ["Truck"]),
        (["heta-arbeten"], ["Heta arbeten"]),
        (["fallskydd", "lift"], ["Fallskydd", "Lift"]),
        (["lift", "fallskydd"], ["Lift", "Fallskydd"]),
        (["säkra-lyft", "heta-arbeten"], ["Säkra lyft", "Heta arbeten"]),
        (["fallskydd", "fallskydd"], ["Fallskydd", "Fallskydd"]),
        (["lift", "lift", "lift"], ["Lift", "Lift", "Lift"]),
        (["unknown"], []),
        (["fallskydd", "unknown", "lift"], ["Fallskydd", "Lift"]),
        (["unknown", "fallskydd", "unknown"], ["Fallskydd"]),
        ([], []),
        (["lift", "Lift"], ["Lift"]),
        (["säkra-lyft", "truck", "heta-arbeten"], ["Säkra lyft", "Truck", "Heta arbeten"]),
        (["truck", "säkra-lyft", "fallskydd"], ["Truck", "Säkra lyft", "Fallskydd"]),
        (["heta-arbeten", "truck", "lift"], ["Heta arbeten", "Truck", "Lift"]),
        (
            ["fallskydd", "säkra-lyft", "heta-arbeten", "truck"],
            ["Fallskydd", "Säkra lyft", "Heta arbeten", "Truck"],
        ),
        (["lift", "lift", "unknown", "truck"], ["Lift", "Lift", "Truck"]),
        (["unknown", "unknown"], []),
        (["säkra-lyft", "säkra-lyft", "säkra-lyft"], ["Säkra lyft", "Säkra lyft", "Säkra lyft"]),
        (["truck", "unknown", "unknown", "truck"], ["Truck", "Truck"]),
        (
            ["heta-arbeten", "fallskydd", "lift", "säkra-lyft", "truck"],
            ["Heta arbeten", "Fallskydd", "Lift", "Säkra lyft", "Truck"],
        ),
        (
            ["fallskydd", "lift", "säkra-lyft", "unknown", "heta-arbeten"],
            ["Fallskydd", "Lift", "Säkra lyft", "Heta arbeten"],
        ),
    ],
)
def test_labels_for_slugs(slugs, expected_labels):
    assert labels_for_slugs(slugs) == expected_labels
