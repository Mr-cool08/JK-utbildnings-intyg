# Copyright (c) Liam Suorsa and Mika Suorsa
import pytest
from flask import render_template

import app


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
        stylesheet = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "@media (prefers-reduced-motion: reduce)" in stylesheet
    assert ".error-general__gear" in stylesheet
    assert "error-general-jam-clockwise" in stylesheet
    assert "animation: none;" in stylesheet
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
