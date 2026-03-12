# Copyright (c) Liam Suorsa and Mika Suorsa
import re

import app


def _client():
    client = app.app.test_client()
    return client


def test_pricing_page_loads(empty_db):
    with _client() as client:
        response = client.get('/pris')
        assert response.status_code == 200
        body = response.data.decode('utf-8')
        assert 'Prislista' in body
        assert '690 kr' in body


def test_home_page_links_pricing(empty_db):
    with _client() as client:
        response = client.get('/')
        assert response.status_code == 200
        body = response.data.decode('utf-8')
        assert '/pris' in body
        assert 'Privatkonto är gratis för privatpersoner.' in body


def test_pricing_page_has_clear_primary_cta_and_adaptive_layout(empty_db):
    with _client() as client:
        response = client.get('/pris')
        assert response.status_code == 200
        body = response.data.decode('utf-8')

    actions_match = re.search(
        r'<div class="pricing-hero-actions"[\s\S]*?</div>',
        body,
    )
    assert actions_match is not None

    actions_block = actions_match.group(0)
    assert actions_block.count('class="btn"') == 1
    assert 'Frågor om pris? Kontakta support' in actions_block
    assert 'mailto:support@utbildningsintyg.se' in actions_block
    assert 'class="pricing-layout"' in body
    assert 'class="pricing-summary"' in body
