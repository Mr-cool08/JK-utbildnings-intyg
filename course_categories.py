"""Konstanter och hjälpmetoder för kurskategorier."""

from __future__ import annotations

from typing import Iterable, List, Tuple

# Lista över tillgängliga kurskategorier (slug, etikett)
COURSE_CATEGORIES: List[Tuple[str, str]] = [
    ("fallskydd", "Fallskydd"),
    ("lift", "Lift"),
    ("säkra-lyft", "Säkra lyft"),
    ("truck", "Truck"),
    ("heta-arbeten", "Heta arbeten"),
]

_CATEGORY_LOOKUP = {slug: label for slug, label in COURSE_CATEGORIES}


def normalize_category_slugs(values: Iterable[str]) -> List[str]:
    """Filtrera och normalisera inkommande kategori-slugs."""

    normalized: List[str] = []
    seen: set[str] = set()
    for raw in values:
        slug = raw.strip().lower()
        if slug and slug in _CATEGORY_LOOKUP and slug not in seen:
            normalized.append(slug)
            seen.add(slug)
    return normalized


def labels_for_slugs(slugs: Iterable[str]) -> List[str]:
    """Returnera svenska etiketter för angivna kategori-slugs."""

    return [_CATEGORY_LOOKUP[slug] for slug in slugs if slug in _CATEGORY_LOOKUP]
