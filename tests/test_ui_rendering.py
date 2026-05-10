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
    assert "Ladda upp intyg" in nav_links
    assert 'href="/dashboard/upload"' in nav_links
    assert 'href="/logout"' in nav_links
    assert "Privatinloggning" not in nav_links
    assert "/foretagskonto/login" not in nav_links


def test_standardkonto_form_contains_expected_ui_fields(empty_db):
    with _client() as client:
        response = client.get("/ansok/standardkonto")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    assert "Skapa privatkonto" in body
    assert 'id="name"' in body
    assert 'id="email"' in body
    assert 'type="email"' in body
    assert 'id="personnummer"' in body
    assert 'inputmode="numeric"' in body
    assert 'placeholder="ÅÅMMDDXXXX"' in body
    assert 'id="orgnr"' in body
    assert 'placeholder="5569668337"' in body
    assert 'id="terms_confirmed"' in body
    assert 'href="/villkor"' in body
    assert 'href="/gdpr"' in body
    assert "form_error_highlight.js" in body
    assert "Skapar konto" in body


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


def test_public_organization_search_page_renders_form(empty_db):
    with _client() as client:
        response = client.get("/organisationer")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    assert "Sök organisationsnummer" in body
    assert 'id="orgnr"' in body
    assert "Registrerade privatkonton" not in body


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
    assert "Mina intyg" in body
    assert "Ladda upp intyg" in body
    assert "dashboard.js" in body


def test_dashboard_shows_search_when_user_has_more_than_five_certificates(user_db):
    personnummer_hash = functions.hash_value("9001011234")
    category_slug = COURSE_CATEGORIES[0][0]

    for index in range(6):
        functions.store_pdf_blob(
            personnummer_hash,
            f"intyg-{index}.pdf",
            f"%PDF-1.4 ui-test-{index}".encode(),
            [category_slug],
        )

    with _client() as client:
        _login_user(client)
        response = client.get("/dashboard")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    assert "Sök intyg" in body
    assert 'data-dashboard-search' in body
    assert 'id="dashboardSearch"' in body


def test_dashboard_hides_search_when_user_has_five_or_fewer_certificates(user_db):
    personnummer_hash = functions.hash_value("9001011234")
    category_slug = COURSE_CATEGORIES[0][0]

    for index in range(5):
        functions.store_pdf_blob(
            personnummer_hash,
            f"kort-{index}.pdf",
            f"%PDF-1.4 small-{index}".encode(),
            [category_slug],
        )

    with _client() as client:
        _login_user(client)
        response = client.get("/dashboard")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    assert "Sök intyg" not in body
    assert 'data-dashboard-search' not in body


def test_dashboard_shows_company_connection_without_details_panel(user_db):
    personnummer_hash = functions.hash_value("9001011234")
    supervisor_hash = functions.hash_value("foretag@example.com")

    with user_db.begin() as conn:
        conn.execute(
            functions.supervisors_table.insert().values(
                name="Handledarbolaget",
                email=supervisor_hash,
                password=functions.hash_password("super-secret-1"),
            )
        )
        conn.execute(
            functions.supervisor_connections_table.insert().values(
                supervisor_email=supervisor_hash,
                user_personnummer=personnummer_hash,
            )
        )

    with _client() as client:
        _login_user(client)
        response = client.get("/dashboard")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    assert "Företagskoppling" in body
    assert "Handledarbolaget" in body
    assert "Ta bort koppling" in body
    assert '<details class="dashboard-secondary">' not in body


def test_upload_page_requires_login(empty_db):
    with _client() as client:
        response = client.get("/dashboard/upload", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_upload_page_renders_form_for_logged_in_user(user_db):
    with _client() as client:
        _login_user(client)
        response = client.get("/dashboard/upload")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    assert "Ladda upp intyg" in body
    assert 'name="csrf_token"' in body
    assert 'id="certificate"' in body
    assert 'id="category"' in body
    assert 'id="note"' in body
    assert "Tillbaka till mina intyg" in body


def test_home_page_exposes_motion_markers(empty_db):
    with _client() as client:
        response = client.get("/")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    assert 'data-motion="hero"' in body
    assert 'data-motion-group="workflow"' in body
    assert 'data-motion-group="features"' in body
    assert 'data-motion-group="benefits"' in body


def test_home_page_head_uses_non_blocking_assets_and_cmp_order(empty_db):
    with _client() as client:
        response = client.get("/")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    cmp_script = "https://cdn.consentmanager.net/delivery/autoblocking/79b762eac2d3b.js"
    clarity_script = "https://www.clarity.ms/tag/"
    google_script = "https://www.googletagmanager.com/gtag/js?id=G-EHG218KKPZ"

    assert body.index(cmp_script) < body.index(clarity_script)
    assert body.index(cmp_script) < body.index(google_script)
    assert 'rel="preconnect" href="https://cdn.consentmanager.net"' in body
    assert 'rel="preconnect" href="https://a.delivery.consentmanager.net"' in body
    assert 'rel="preload" href="/static/css/base.css"' in body
    assert 'media="print" onload="this.media=\'all\'"' in body
    assert 'type="text/plain" class="cmplazyload" data-cmp-vendor="s2631"' in body
    assert 'type="text/plain" class="cmplazyload" data-cmp-vendor="s26"' in body


def test_logo_asset_is_optimized_for_small_ui_slots():
    logo_path = Path("static/pictures/favicon_smaller.png")
    data = logo_path.read_bytes()

    assert data.startswith(b"\x89PNG\r\n\x1a\n")
    assert int.from_bytes(data[16:20], "big") == 80
    assert int.from_bytes(data[20:24], "big") == 80
    assert logo_path.stat().st_size < 10_000


def test_home_page_logo_images_declare_explicit_dimensions(empty_db):
    with _client() as client:
        response = client.get("/")
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    assert 'class="brand-logo"' in body
    assert 'width="40"' in body
    assert 'height="40"' in body
    assert 'width="30"' in body
    assert 'height="30"' in body


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
