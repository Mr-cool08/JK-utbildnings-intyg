# Copyright (c) Liam Suorsa
"""Omfattande tester för kurskategori-hjälpfunktioner."""

import pytest

from course_categories import labels_for_slugs, normalize_category_slugs


@pytest.mark.parametrize(
    "input_values, expected",
    [
        (["fallskydd-grund"], ["fallskydd-grund"]),
        (["FALLSKYDD-GRUND"], ["fallskydd-grund"]),
        ([" Liftutbildning "], ["liftutbildning"]),
        (["truckutbildning-a", "truckutbildning-a"], ["truckutbildning-a"]),
        (["heta-arbeten", "unknown"], ["heta-arbeten"]),
        (["unknown"], []),
        (["fallskydd-grund", "liftutbildning"], ["fallskydd-grund", "liftutbildning"]),
        (["liftutbildning", "fallskydd-grund"], ["liftutbildning", "fallskydd-grund"]),
        (["", " "], []),
        (["säKRA-Lyft"], ["säkra-lyft"]),
        (["Fallskydd-grund", "fallskydd-grund", "FALLSKYDD-GRUND"], ["fallskydd-grund"]),
        (["fallskydd-grund", " liftutbildning "], ["fallskydd-grund", "liftutbildning"]),
        ([" Heta-Arbeten "], ["heta-arbeten"]),
        (
            ["truckutbildning-a", "Liftutbildning", "Säkra-Lyft"],
            ["truckutbildning-a", "liftutbildning", "säkra-lyft"],
        ),
        (["liftutbildning", "Liftutbildning", "liftutbildning "], ["liftutbildning"]),
        (["säkrA-lyft", "TRUCKUTBILDNING-A", "unknown"], ["säkra-lyft", "truckutbildning-a"]),
        (["FALLSKYDD-GRUND", "liftutbildning", "Liftutbildning"], ["fallskydd-grund", "liftutbildning"]),
        (["\tsäkra-lyft\n"], ["säkra-lyft"]),
        (["fallskydd-grund", "unknown", " liftutbildning "], ["fallskydd-grund", "liftutbildning"]),
        (
            ["TRUCKUTBILDNING-A", "Fallskydd-grund", "Liftutbildning", "HETA-ARBETEN"],
            ["truckutbildning-a", "fallskydd-grund", "liftutbildning", "heta-arbeten"],
        ),
        (
            ["liftutbildning", "säkra-lyft", "fallskydd-grund", "liftutbildning"],
            ["liftutbildning", "säkra-lyft", "fallskydd-grund"],
        ),
        (["truckutbildning-a", "   ", "heta-arbeten"], ["truckutbildning-a", "heta-arbeten"]),
        (["liftutbildning", "Liftutbildning", "LIFTUTBILDNING", "liftutbildning"], ["liftutbildning"]),
        (
            [" fallskydd-grund ", " säkra-lyft ", "unknown", "truckutbildning-a"],
            ["fallskydd-grund", "säkra-lyft", "truckutbildning-a"],
        ),
        (["HETA-ARBETEN", " SäKrA-LyFt "], ["heta-arbeten", "säkra-lyft"]),
    ],
)
def test_normalize_category_slugs(input_values, expected):
    assert normalize_category_slugs(input_values) == expected


@pytest.mark.parametrize(
    "slugs, expected_labels",
    [
        (["fallskydd-grund"], ["Fallskydd – grund"]),
        (["liftutbildning"], ["Liftutbildning"]),
        (["säkra-lyft"], ["Säkra lyft"]),
        (["truckutbildning-a"], ["Truckutbildning A"]),
        (["heta-arbeten"], ["Heta Arbeten"]),
        (["fallskydd-grund", "liftutbildning"], ["Fallskydd – grund", "Liftutbildning"]),
        (["liftutbildning", "fallskydd-grund"], ["Liftutbildning", "Fallskydd – grund"]),
        (["säkra-lyft", "heta-arbeten"], ["Säkra lyft", "Heta Arbeten"]),
        (["fallskydd-grund", "fallskydd-grund"], ["Fallskydd – grund", "Fallskydd – grund"]),
        (["liftutbildning", "liftutbildning", "liftutbildning"], ["Liftutbildning", "Liftutbildning", "Liftutbildning"]),
        (["unknown"], []),
        (["fallskydd-grund", "unknown", "liftutbildning"], ["Fallskydd – grund", "Liftutbildning"]),
        (["unknown", "fallskydd-grund", "unknown"], ["Fallskydd – grund"]),
        ([], []),
        (["liftutbildning", "Liftutbildning"], ["Liftutbildning"]),
        (
            ["säkra-lyft", "truckutbildning-a", "heta-arbeten"],
            ["Säkra lyft", "Truckutbildning A", "Heta Arbeten"],
        ),
        (
            ["truckutbildning-a", "säkra-lyft", "fallskydd-grund"],
            ["Truckutbildning A", "Säkra lyft", "Fallskydd – grund"],
        ),
        (
            ["heta-arbeten", "truckutbildning-a", "liftutbildning"],
            ["Heta Arbeten", "Truckutbildning A", "Liftutbildning"],
        ),
        (
            ["fallskydd-grund", "säkra-lyft", "heta-arbeten", "truckutbildning-a"],
            ["Fallskydd – grund", "Säkra lyft", "Heta Arbeten", "Truckutbildning A"],
        ),
        (["liftutbildning", "liftutbildning", "unknown", "truckutbildning-a"], ["Liftutbildning", "Liftutbildning", "Truckutbildning A"]),
        (["unknown", "unknown"], []),
        (
            ["säkra-lyft", "säkra-lyft", "säkra-lyft"],
            ["Säkra lyft", "Säkra lyft", "Säkra lyft"],
        ),
        (["truckutbildning-a", "unknown", "unknown", "truckutbildning-a"], ["Truckutbildning A", "Truckutbildning A"]),
        (
            ["heta-arbeten", "fallskydd-grund", "liftutbildning", "säkra-lyft", "truckutbildning-a"],
            ["Heta Arbeten", "Fallskydd – grund", "Liftutbildning", "Säkra lyft", "Truckutbildning A"],
        ),
        (
            ["fallskydd-grund", "liftutbildning", "säkra-lyft", "unknown", "heta-arbeten"],
            ["Fallskydd – grund", "Liftutbildning", "Säkra lyft", "Heta Arbeten"],
        ),
    ],
)
def test_labels_for_slugs(slugs, expected_labels):
    assert labels_for_slugs(slugs) == expected_labels
