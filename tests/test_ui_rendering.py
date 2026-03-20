import re
from pathlib import Path

import app
import functions
from course_categories import COURSE_CATEGORIES


def _client():
    return app.app.test_client()


def _extract_nav_links(body: str) -> str:
    match = re.search(r'<div class="nav-links">(.*?)</div>', body, flags=re.DOTALL)
    assert match is not None
    return match.group(1)


def _login_user(client):
    with client.session_transaction() as session:
        session["csrf_token"] = "test-token"
    response = client.post(
        "/login",
        data={
            "personnummer": "9001011234",
            "password": "secret",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302


def test_public_nav_shows_public_links_and_swedish_lang(empty_db):
    with _client() as client:
        response = client.get("/")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    nav_links = _extract_nav_links(body)

    assert '<html lang="sv">' in body
    assert ">Hem<" in nav_links
    assert 'href="/ansok"' in nav_links
    assert 'href="/foretagskonto/login"' in nav_links
    assert 'href="/login"' in nav_links


def test_logged_in_user_nav_shows_user_actions_only(user_db):
    with _client() as client:
        _login_user(client)
        response = client.get("/dashboard")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    nav_links = _extract_nav_links(body)

    assert ">Intyg<" in nav_links
    assert 'href="/logout"' in nav_links
    assert "Privatinloggning" not in nav_links
    assert "/foretagskonto/login" not in nav_links


def test_standardkonto_form_contains_expected_ui_fields(empty_db):
    with _client() as client:
        response = client.get("/ansok/standardkonto")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    assert "Ansök om privatkonto" in body
    assert "Privatkontot är gratis." in body
    assert (
        "du behöver inte vara kopplad till en arbetsgivare"
        in body
    )
    assert "Privatkonto är gratis för privatpersoner." in body
    assert (
        "Du kan ansöka även om din arbetsgivare inte använder "
        "Utbildningsintyg idag."
        in body
    )
    assert 'id="name"' in body
    assert 'id="email"' in body
    assert 'type="email"' in body
    assert 'id="personnummer"' in body
    assert 'inputmode="numeric"' in body
    assert 'placeholder="ÅÅMMDDXXXX"' in body
    assert 'id="terms_confirmed"' in body
    assert 'href="/villkor"' in body
    assert 'href="/gdpr"' in body
    assert "form_error_highlight.js" in body
    assert "Skickar ansökan" in body


def test_foretagskonto_form_contains_invoice_section_and_required_fields(empty_db):
    with _client() as client:
        response = client.get("/ansok/foretagskonto")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    assert "Ansök om företagskonto" in body
    assert 'id="company_name"' in body
    assert 'id="orgnr"' in body
    assert 'inputmode="numeric"' in body
    assert "556966-8337" in body
    assert 'id="invoiceSection"' in body
    assert 'id="invoice_address"' in body
    assert 'id="invoice_contact"' in body
    assert 'id="invoice_reference"' in body
    assert 'id="terms_confirmed"' in body
    assert 'href="/villkor"' in body
    assert 'href="/gdpr"' in body
    assert "form_error_highlight.js" in body


def test_apply_page_clarifies_private_account_is_free_and_independent(empty_db):
    with _client() as client:
        response = client.get("/ansok")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    assert "För privatpersoner som vill samla och dela sina egna intyg." in body
    assert (
        "Du kan ansöka som privatperson även utan koppling till en arbetsgivare."
        in body
    )
    assert "Privatkonto kostar inget att ansöka om eller använda." in body


def test_dashboard_ui_contains_share_modal_for_logged_in_user(user_db):
    personnummer_hash = functions.hash_value("9001011234")
    category_slug = COURSE_CATEGORIES[0][0]
    functions.store_pdf_blob(
        personnummer_hash,
        "ui-intyg.pdf",
        b"%PDF-1.4 ui-test",
        [category_slug],
    )

    with _client() as client:
        _login_user(client)
        response = client.get("/dashboard")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    assert "Dela markerade intyg" in body
    assert 'id="shareModal"' in body
    assert 'id="shareRecipientEmail"' in body
    assert "data-share-select" in body
    assert 'id="certificate"' in body
    assert 'id="category"' in body
    assert "dashboard.js" in body


def test_home_page_exposes_motion_markers(empty_db):
    with _client() as client:
        response = client.get("/")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    assert 'data-motion="hero"' in body
    assert "Välj kontotyp" in body
    assert "Andra vägar" in body
    assert 'data-motion-group="workflow"' in body
    assert 'data-motion-group="features"' in body
    assert 'data-motion-group="benefits"' in body


def test_home_page_repeats_account_type_choices_in_final_cta(empty_db):
    with _client() as client:
        response = client.get("/")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    cta_match = re.search(
        r'<section class="cta-panel"[\s\S]*?</section>',
        body,
    )
    assert cta_match is not None
    cta_body = cta_match.group(0)

    assert "Välj kontotyp för att fortsätta" in body
    assert body.count('href="/ansok/standardkonto"') >= 2
    assert body.count('href="/ansok/foretagskonto"') >= 2
    assert "Ansök om konto" not in cta_body



def test_home_page_hero_places_choice_list_inside_action_panel(empty_db):
    with _client() as client:
        response = client.get("/")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    actions_index = body.index('class="hero-actions"')
    choice_list_index = body.index('class="hero-choice-list"')

    assert actions_index < choice_list_index

def test_apply_and_pricing_pages_expose_motion_markers(empty_db):
    with _client() as client:
        apply_response = client.get("/ansok")
        assert apply_response.status_code == 200
        apply_body = apply_response.get_data(as_text=True)

        pricing_response = client.get("/pris")
        assert pricing_response.status_code == 200
        pricing_body = pricing_response.get_data(as_text=True)

    assert 'data-motion-group="apply-options"' in apply_body
    assert 'data-motion-group="apply-steps"' in apply_body
    assert 'data-motion-group="pricing-sections"' in pricing_body
    assert 'data-motion="section"' in pricing_body


def test_motion_assets_support_reduced_motion():
    nav_script = Path("static/js/nav.js").read_text(encoding="utf-8")
    base_css = Path("static/css/base.css").read_text(encoding="utf-8")

    assert "prefers-reduced-motion: reduce" in nav_script
    assert "IntersectionObserver" in nav_script
    assert ".has-motion .motion-ready" in base_css
    assert ".motion-ready.is-visible" in base_css
    assert "@media (prefers-reduced-motion: reduce)" in base_css


# Copyright (c) Liam Suorsa and Mika Suorsa
