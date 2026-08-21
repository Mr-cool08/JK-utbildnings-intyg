# Copyright (c) Liam Suorsa and Mika Suorsa
import app


def _client():
    client = app.app.test_client()
    return client


def test_pricing_page_loads(empty_db):
    with _client() as client:
        response = client.get('/pris')
        assert response.status_code == 200
        body = response.data.decode('utf-8')
        assert '<h1 id="pricing-page-title">Priser</h1>' in body
        assert '690 kr' in body


def test_home_page_links_pricing(empty_db):
    with _client() as client:
        response = client.get('/')
        assert response.status_code == 200
        body = response.data.decode('utf-8')
        assert '/pris' in body
        assert 'Privatkonto är gratis för privatpersoner.' in body


def test_pricing_page_has_direct_actions_and_distilled_content(empty_db):
    with _client() as client:
        response = client.get('/pris')
        assert response.status_code == 200
        body = response.data.decode('utf-8')

    assert 'class="pricing-layout"' in body
    assert 'href="/ansok/foretagskonto"' in body
    assert 'href="/ansok/standardkonto"' in body
    assert 'mailto:support@utbildningsintyg.se' in body
    assert 'pricing-included' not in body
    assert 'pricing-summary' not in body
    assert 'Tre enkla steg' not in body


def test_pricing_page_exposes_tiers_and_direct_plan_actions(empty_db):
    with _client() as client:
        response = client.get('/pris')
        assert response.status_code == 200
        body = response.get_data(as_text=True)

    expected_tiers = (
        ('1–10', '190 kr'),
        ('11–20', '390 kr'),
        ('21–50', '690 kr'),
    )
    for user_range, monthly_price in expected_tiers:
        assert user_range in body
        assert monthly_price in body

    assert 'Pris per månad efter antal anslutna användare' in body
    assert 'Företagspriserna anges exklusive moms.' in body
    assert 'Fakturering sker årsvis.' in body
    assert '<strong>0 kr</strong>' in body
    assert 'href="/ansok/foretagskonto"' in body
    assert 'href="/ansok/standardkonto"' in body
    assert 'aria-labelledby="company-plan-title"' in body
    assert 'css/pricing.css' in body


def test_pricing_page_styles_use_shared_theme_tokens(empty_db):
    with _client() as client:
        response = client.get('/static/css/pricing.css')
        assert response.status_code == 200
        stylesheet = response.get_data(as_text=True)

    assert 'var(--color-primary)' in stylesheet
    assert 'var(--color-surface)' in stylesheet
    assert 'var(--shadow-md)' in stylesheet
    assert '--pricing-' not in stylesheet
