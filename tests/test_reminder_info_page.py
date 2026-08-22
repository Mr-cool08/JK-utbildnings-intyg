"""Tester för den publika informationssidan om utgångspåminnelser."""

import json
import re

import app


def _client():
    return app.app.test_client()


def _page_body():
    with _client() as client:
        response = client.get("/paminnelse-utbildningsintyg")

    assert response.status_code == 200
    return response.get_data(as_text=True)


def test_reminder_info_page_is_public_and_has_unique_seo_metadata(empty_db):
    body = _page_body()

    assert (
        "<title>Påminnelse för utbildningsintyg – bevaka utgångsdatum</title>"
        in body
    )
    assert body.count("<h1") == 1
    assert "Påminnelse när utbildningsintyg och certifikat går ut" in body
    assert (
        '<meta name="description" content="Få påminnelse när utbildningsintyg '
        "eller certifikat går ut. Se hur du bevakar utgångsdatum och håller koll "
        'på personalens utbildningar.">' in body
    )
    assert '<meta name="robots" content="index, follow">' in body
    assert (
        '<link rel="canonical" '
        'href="https://www.utbildningsintyg.se/paminnelse-utbildningsintyg">'
        in body
    )
    assert (
        '<meta property="og:url" '
        'content="https://www.utbildningsintyg.se/paminnelse-utbildningsintyg">'
        in body
    )


def test_reminder_info_page_explains_actual_private_and_company_flow(empty_db):
    body = _page_body()

    expected_copy = (
        "I standardkonfigurationen kontrolleras registret varje månad.",
        "Efter ett lyckat utskick kan intyget påminnas igen vid en",
        "Bevakningen startar först när intyget har ett registrerat",
        "Privatkontots ägare får en egen sammanfattning.",
        "företaget också en separat översikt, grupperad per kopplad",
        "Få åtkomst först efter att privatpersonen har godkänt kopplingen.",
        "Bildfiler sparas som PDF",
        "Du kan också välja att ett intyg inte har något utgångsdatum.",
    )
    for copy in expected_copy:
        assert copy in body

    assert "SMS" not in body
    assert "pushnotis" not in body
    assert "verifierar intygets äkthet" not in body


def test_reminder_info_page_uses_priority_phrases_naturally(empty_db):
    body = _page_body().lower()

    priority_phrases = (
        "utbildningsintyg utgångsdatum",
        "certifikat utgångsdatum",
        "utbildningsregister med påminnelser",
        "automatiska påminnelser utbildningsintyg",
        "digitalt utbildningsregister",
        "system för certifikatpåminnelser",
        "hålla koll på personalens utbildningar",
        "certifikathantering med påminnelser",
    )
    for phrase in priority_phrases:
        assert phrase in body


def test_reminder_info_page_exposes_valid_faq_structured_data(empty_db):
    body = _page_body()
    match = re.search(
        r'<script type="application/ld\+json">\s*(.*?)\s*</script>',
        body,
        flags=re.DOTALL,
    )

    assert match is not None
    structured_data = json.loads(match.group(1))
    graph = structured_data["@graph"]
    faq_page = next(item for item in graph if item["@type"] == "FAQPage")

    assert len(faq_page["mainEntity"]) == 4
    questions = {item["name"] for item in faq_page["mainEntity"]}
    assert "Hur håller man koll på utbildningar som går ut?" in questions
    assert "När skickas en påminnelse om ett utbildningsintyg?" in questions
    assert "Vem får mejlet när ett certifikat går ut?" in questions
    assert "Vad händer om ett intyg saknar utgångsdatum?" in questions


def test_reminder_info_page_links_to_account_creation_and_pricing(empty_db):
    body = _page_body()

    assert 'href="/ansok">Skapa konto</a>' in body
    assert 'href="/pris">Se priser</a>' in body


# Copyright (c) Liam Suorsa and Mika Suorsa
