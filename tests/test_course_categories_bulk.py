# Copyright (c) Liam Suorsa and Mika Suorsa
"""Tester för kurskategorier och migrering av äldre kategori-slugs."""

from collections import Counter

import pytest

from course_categories import (
    COURSE_CATEGORIES,
    LEGACY_CATEGORY_SLUG_MAP,
    labels_for_slugs,
    migrate_legacy_category_slugs,
    normalize_category_slugs,
)


EXPECTED_COURSE_CATEGORIES = [
    ("arbetsmiljo-sakerhet", "🦺 Arbetsmiljö & säkerhet"),
    ("bygg-anlaggning-industri", "🏗️ Bygg, anläggning & industri"),
    ("jarnvag-vag", "🚆 Järnväg och väg"),
    ("transport-logistik", "🚚 Transport & logistik"),
    ("it-teknik-administration", "💻 IT, teknik & administration"),
    (
        "ledarskap-hr-mjuka-fardigheter",
        "👥 Ledarskap, HR & mjuka färdigheter",
    ),
    ("vard-omsorg-samhalle", "🏥 Vård, omsorg & samhälle"),
    ("jordbruk-skog-naturbruk", "🌲 Jordbruk, skog & naturbruk"),
    ("utbildning-pedagogik", "📚 Utbildning & pedagogik"),
    ("ekonomi-juridik-affar", "💼 Ekonomi, juridik & affär"),
    ("ovrigt", "🗂️ Övrigt"),
]


def test_course_categories_match_requested_list():
    assert COURSE_CATEGORIES == EXPECTED_COURSE_CATEGORIES


def test_all_legacy_categories_map_to_existing_categories():
    current_slugs = {slug for slug, _label in COURSE_CATEGORIES}
    expected_legacy_targets = {
        "arbetsmiljo-sakerhet",
        "bygg-anlaggning-industri",
        "jarnvag-vag",
        "transport-logistik",
        "it-teknik-administration",
        "ledarskap-hr-mjuka-fardigheter",
        "vard-omsorg-samhalle",
    }

    assert len(LEGACY_CATEGORY_SLUG_MAP) == 149
    assert set(LEGACY_CATEGORY_SLUG_MAP.values()) == expected_legacy_targets
    assert expected_legacy_targets <= current_slugs
    assert Counter(LEGACY_CATEGORY_SLUG_MAP.values()) == {
        "arbetsmiljo-sakerhet": 27,
        "bygg-anlaggning-industri": 22,
        "jarnvag-vag": 20,
        "transport-logistik": 33,
        "it-teknik-administration": 17,
        "ledarskap-hr-mjuka-fardigheter": 18,
        "vard-omsorg-samhalle": 12,
    }
    assert LEGACY_CATEGORY_SLUG_MAP["fallskydd"] == "bygg-anlaggning-industri"
    assert LEGACY_CATEGORY_SLUG_MAP["lift"] == "bygg-anlaggning-industri"
    assert LEGACY_CATEGORY_SLUG_MAP["truck"] == "transport-logistik"


@pytest.mark.parametrize(
    "input_values, expected",
    [
        (["arbetsmiljo-sakerhet"], ["arbetsmiljo-sakerhet"]),
        ([" JARNVAG-VAG "], ["jarnvag-vag"]),
        (
            ["transport-logistik", "Transport-Logistik", "ovrigt"],
            ["transport-logistik", "ovrigt"],
        ),
        (["fallskydd-grund", "unknown", ""], []),
        ([], []),
    ],
)
def test_normalize_category_slugs(input_values, expected):
    assert normalize_category_slugs(input_values) == expected


@pytest.mark.parametrize(
    "slugs, expected_labels",
    [
        (["arbetsmiljo-sakerhet"], ["🦺 Arbetsmiljö & säkerhet"]),
        (
            ["jarnvag-vag", "jordbruk-skog-naturbruk"],
            ["🚆 Järnväg och väg", "🌲 Jordbruk, skog & naturbruk"],
        ),
        (["unknown", "ovrigt"], ["🗂️ Övrigt"]),
        ([], []),
    ],
)
def test_labels_for_slugs(slugs, expected_labels):
    assert labels_for_slugs(slugs) == expected_labels


@pytest.mark.parametrize(
    "legacy_slugs, expected",
    [
        (["heta-arbeten"], ["arbetsmiljo-sakerhet"]),
        (["fallskydd-grund"], ["bygg-anlaggning-industri"]),
        (["allman-jarnvagsteknik"], ["jarnvag-vag"]),
        (["apv-steg-1-grundkompetens"], ["transport-logistik"]),
        (["gdpr-grund"], ["it-teknik-administration"]),
        (
            ["pedagogik-retorik"],
            ["ledarskap-hr-mjuka-fardigheter"],
        ),
        (["basala-hygienrutiner"], ["vard-omsorg-samhalle"]),
        (
            ["fallskydd", "lift", "truck"],
            ["bygg-anlaggning-industri", "transport-logistik"],
        ),
        (
            ["fallskydd-grund", "liftutbildning", "truckutbildning-a"],
            ["bygg-anlaggning-industri", "transport-logistik"],
        ),
        (
            [" JARNVAG-VAG ", "Egen-kategori", "Egen-kategori"],
            ["jarnvag-vag", "Egen-kategori"],
        ),
        (["", "   "], []),
    ],
)
def test_migrate_legacy_category_slugs(legacy_slugs, expected):
    assert migrate_legacy_category_slugs(legacy_slugs) == expected
