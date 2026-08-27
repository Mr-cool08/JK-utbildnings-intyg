# Copyright (c) Liam Suorsa and Mika Suorsa
import pytest
from flask import render_template

import app


def test_custom_403_page():
    with app.app.test_client() as client:
        response = client.get("/foretagskonto/standardkonto/test/pdf/1")
        page = response.get_data(as_text=True)

        assert response.status_code == 403
        assert "Åtkomst nekad (403)" in page
        assert "Stopp vid dörren" in page
        assert "Du har inte behörighet att se den här sidan." in page
        assert '<meta name="robots" content="noindex">' in page
        assert "css/error.css" in page
        assert 'class="error-403"' in page
        assert 'class="error-403__gatekeeper"' in page
        assert "Ett nyckelkort försöker komma in" in page
        assert 'class="btn error-403__home-link" href="/"' in page
        assert 'class="error-404"' not in page
        assert 'class="error-general"' not in page


def test_custom_404_page():
    with app.app.test_client() as client:
        response = client.get("/this-page-does-not-exist")
        page = response.get_data(as_text=True)

        assert response.status_code == 404
        assert "Sidan du letade efter" in page
        assert 'class="error-404"' in page
        assert 'class="error-404__face"' in page
        assert "Siffrorna 404 formas till ett ansikte" in page
        assert "css/error.css" in page


@pytest.mark.parametrize(
    ("error_code", "error_message"),
    [
        (401, "Du måste logga in för att komma åt den här sidan."),
        (409, "Begäran kunde inte genomföras på grund av en konflikt."),
        (413, "Filen är för stor."),
        (500, "Ett internt serverfel har inträffat."),
    ],
)
def test_general_error_layout_does_not_show_404_animation(
    error_code,
    error_message,
):
    with app.app.test_request_context("/"):
        page = render_template(
            "error.html",
            error_code=error_code,
            error_message=error_message,
            time=0,
        )

    assert 'class="error-404"' not in page
    assert 'class="error-403"' not in page
    assert 'class="error-general"' in page
    assert "css/error.css" in page
    assert page.count('class="error-general__gear ') == 3
    assert f"Fel ({error_code})" in page
    assert "Något gick fel" in page
    assert "support@utbildningsintyg.se" in page
    assert f"subject=Fel%20{error_code}" in page
    assert f"inkludera felkoden {error_code} samt tiden ovan" in page


def test_error_animations_respect_reduced_motion():
    with app.app.test_client() as client:
        response = client.get("/static/css/error.css")
        stylesheet = response.get_data(as_text=True).replace("\r\n", "\n")

    assert response.status_code == 200
    assert "@media (prefers-reduced-motion: reduce)" in stylesheet
    assert ".error-general__gear" in stylesheet
    assert "error-general-jam-clockwise" in stylesheet
    assert "error-403-pass-tries" in stylesheet
    assert "animation: none;" in stylesheet
    assert (
        ".error-403__pass {\n"
        "        transform: translate(0.8rem, 0.9rem) rotate(-9deg);\n"
        "    }"
    ) in stylesheet
    assert (
        ".error-403__refusal {\n"
        "        opacity: 1;\n"
        "        transform: scale(1);\n"
        "    }"
    ) in stylesheet
    assert (
        ".error-404__face-eyes {\n"
        "        transform: translate(0, 112.5px);\n"
        "    }"
    ) in stylesheet
    assert (
        ".error-404__face-nose,\n"
        "    .error-404__face-pupil {\n"
        "        transform: translate(0, 0);\n"
        "    }"
    ) in stylesheet
    assert (
        ".error-404__face-pupil {\n"
        "        stroke-dashoffset: 0;\n"
        "    }"
    ) in stylesheet
    assert (
        ".error-404__face-mouth-left {\n"
        "        stroke-dashoffset: -102;\n"
        "    }"
    ) in stylesheet
    assert (
        ".error-404__face-mouth-right {\n"
        "        stroke-dashoffset: 102;\n"
        "    }"
    ) in stylesheet
