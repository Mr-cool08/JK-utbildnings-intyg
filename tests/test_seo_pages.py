"""Regressionstester för publika guider om utbildningsintyg."""

from html import unescape
from pathlib import Path
import re

import pytest

import app


SEO_PAGES = (
    {
        "path": "/digitala-utbildningsintyg",
        "title": "Digitala utbildningsintyg – Samla alla intyg online",
        "description": (
            "Samla utbildningsintyg digitalt och få tillgång till dem från mobil "
            "och dator. Spara, hitta och dela utbildningsbevis enkelt via ditt konto."
        ),
        "h1": "Digitala utbildningsintyg – samla allt på ett ställe",
        "image": "digitala-utbildningsintyg-mobil-dator.webp",
        "alt": "Digitala utbildningsintyg tillgängliga på mobil och dator",
        "links": (
            "/utbildningsintyg-for-foretag",
            "/dela-utbildningsintyg",
            "/lagra-utbildningsintyg-digitalt",
        ),
    },
    {
        "path": "/hantera-utbildningsintyg",
        "title": "Hantera utbildningsintyg enkelt på ett ställe",
        "description": (
            "Slipp mappar, mejl och Excel. Samla och hantera utbildningsintyg "
            "digitalt, hitta rätt intyg snabbt och få bättre kontroll över "
            "giltighetstider."
        ),
        "h1": "Hantera utbildningsintyg utan mappar, mejl och kalkylblad",
        "image": "hantera-utbildningsintyg-digitalt.webp",
        "alt": "Hantera och samla utbildningsintyg digitalt på ett ställe",
        "links": (
            "/utbildningsintyg-for-foretag",
            "/kompetensregister",
            "/lagra-utbildningsintyg-digitalt",
        ),
    },
    {
        "path": "/utbildningsintyg-for-foretag",
        "title": "Utbildningsintyg för företag – Kontroll på personalens intyg",
        "description": (
            "Samla personalens utbildningsintyg i ett digitalt register. Se "
            "giltighetstider, hitta intyg snabbt och få påminnelser om intyg som "
            "snart går ut."
        ),
        "h1": ("Utbildningsintyg för företag – få kontroll på personalens intyg"),
        "image": "utbildningsintyg-for-foretag.webp",
        "alt": "Företag som hanterar personalens utbildningsintyg digitalt",
        "links": (
            "/kompetensregister",
            "/hall-koll-pa-personalens-utbildningar",
        ),
    },
    {
        "path": "/kompetensregister",
        "title": "Kompetensregister – Digital kontroll på personalens utbildningar",
        "description": (
            "Skapa ett digitalt kompetensregister för företagets personal. Samla "
            "utbildningsintyg, följ giltighetstider och se vilka utbildningar som "
            "behöver förnyas."
        ),
        "h1": "Digitalt kompetensregister för personalens utbildningar",
        "image": "digitalt-kompetensregister.webp",
        "alt": "Digitalt kompetensregister för personalens utbildningar",
        "links": (
            "/utbildningsintyg-for-foretag",
            "/hall-koll-pa-personalens-utbildningar",
        ),
    },
    {
        "path": "/hall-koll-pa-personalens-utbildningar",
        "title": "Så håller du koll på personalens utbildningar och intyg",
        "description": (
            "Få kontroll över personalens utbildningar, certifikat och "
            "utgångsdatum. Se hur ett digitalt utbildningsregister minskar "
            "administration och missade förnyelser."
        ),
        "h1": "Så håller du koll på personalens utbildningar",
        "image": "hall-koll-personal-utbildningar.webp",
        "alt": "Översikt över personalens utbildningar och giltighetstider",
        "links": (
            "/utbildningsintyg-for-foretag",
            "/kompetensregister",
        ),
    },
    {
        "path": "/lagra-utbildningsintyg-digitalt",
        "title": ("Lagra utbildningsintyg digitalt – Samlat och lättillgängligt"),
        "description": (
            "Lagra utbildningsintyg digitalt istället för i pärmar och mejl. Få "
            "ett sökbart arkiv som är tillgängligt från mobil, surfplatta och "
            "dator."
        ),
        "h1": ("Lagra utbildningsintyg digitalt och hitta dem när du behöver dem"),
        "image": "lagra-utbildningsintyg-digitalt.webp",
        "alt": ("Digital lagring av utbildningsintyg i ett inloggningsskyddat arkiv"),
        "links": (
            "/hantera-utbildningsintyg",
            "/utbildningsintyg-for-foretag",
            "/gdpr-utbildningsintyg",
        ),
    },
    {
        "path": "/dela-utbildningsintyg",
        "title": "Dela utbildningsintyg digitalt – Snabbt och enkelt",
        "description": (
            "Dela utbildningsintyg digitalt med arbetsgivare, kunder och andra "
            "mottagare. Hitta rätt intyg och skicka det som PDF-bilaga via e-post."
        ),
        "h1": "Dela utbildningsintyg digitalt när någon behöver se dem",
        "image": "dela-utbildningsintyg-digitalt.webp",
        "alt": "Dela utbildningsintyg digitalt med arbetsgivare eller kund",
        "links": (
            "/lagra-utbildningsintyg-digitalt",
            "/utbildningsintyg-for-foretag",
        ),
    },
    {
        "path": "/gdpr-utbildningsintyg",
        "title": "Utbildningsintyg och GDPR – Säker hantering av personuppgifter",
        "description": (
            "Hur ska utbildningsintyg hanteras enligt GDPR? Läs om säker digital "
            "lagring, personuppgifter, åtkomst och hantering av företagets "
            "utbildningsintyg."
        ),
        "h1": "Utbildningsintyg och GDPR – vad behöver företag tänka på?",
        "image": "gdpr-utbildningsintyg.webp",
        "alt": ("Säker hantering av utbildningsintyg och personuppgifter enligt GDPR"),
        "links": (
            "/lagra-utbildningsintyg-digitalt",
            "/utbildningsintyg-for-foretag",
        ),
    },
)


def _client():
    return app.app.test_client()


def _visible_text(body: str) -> str:
    without_markup = re.sub(r"<[^>]+>", " ", body)
    return re.sub(r"\s+", " ", unescape(without_markup)).strip()


@pytest.mark.parametrize("page", SEO_PAGES, ids=lambda page: page["path"])
def test_seo_page_is_public_indexable_and_complete(page, empty_db):
    with _client() as client:
        response = client.get(page["path"])
        image_response = client.get(f"/static/pictures/{page['image']}")

    assert response.status_code == 200
    assert image_response.status_code == 200
    assert image_response.content_type == "image/webp"
    body = response.get_data(as_text=True)
    canonical = f"https://www.utbildningsintyg.se{page['path']}"
    image_url = f"/static/pictures/{page['image']}"
    og_image = f"https://www.utbildningsintyg.se{image_url}"

    assert f"<title>{page['title']}</title>" in body
    assert f'<meta name="description" content="{page["description"]}">' in body
    assert '<meta name="robots" content="index, follow">' in body
    assert "noindex" not in body.lower()
    assert f'<link rel="canonical" href="{canonical}">' in body
    assert f'<meta property="og:title" content="{page["title"]}">' in body
    assert f'<meta property="og:description" content="{page["description"]}">' in body
    assert f'<meta property="og:url" content="{canonical}">' in body
    assert '<meta property="og:type" content="website">' in body
    assert f'<meta property="og:image" content="{og_image}">' in body
    assert f'<meta property="og:image:alt" content="{page["alt"]}">' in body
    assert f'src="{image_url}"' in body
    assert f'alt="{page["alt"]}"' in body
    assert '<meta property="og:image:width" content="1536">' in body
    assert '<meta property="og:image:height" content="1024">' in body
    assert body.count("<h1") == 1
    assert page["h1"] in _visible_text(body)
    assert '<div class="reminder-faq__list">' in body
    assert "<details" in body
    assert '<section class="reminder-cta"' in body

    asset_path = Path("static/pictures") / page["image"]
    assert asset_path.is_file()
    assert asset_path.stat().st_size > 0

    for link in page["links"]:
        assert f'href="{link}"' in body


def test_seo_pages_have_distinct_titles_descriptions_and_h1s():
    for key in ("title", "description", "h1"):
        values = [page[key] for page in SEO_PAGES]
        assert len(values) == len(set(values))


def test_seo_hero_media_reserves_space_for_captions():
    stylesheet = Path("static/css/base.css").read_text(encoding="utf-8")
    stylesheet = stylesheet.replace("\r\n", "\n")
    figure_rule = re.search(
        r"\.seo-hero__media \{(?P<body>.*?)\n\}", stylesheet, re.DOTALL
    )
    image_rule = re.search(
        r"\.seo-hero__media img \{(?P<body>.*?)\n\}", stylesheet, re.DOTALL
    )

    assert figure_rule is not None
    assert image_rule is not None
    assert "aspect-ratio" not in figure_rule.group("body")
    assert "height: auto;" in image_rule.group("body")
    assert "aspect-ratio: 3 / 2;" in image_rule.group("body")
    assert ".seo-hero__media figcaption" in stylesheet


def test_seo_pages_keep_product_and_legal_boundaries_explicit(empty_db):
    with _client() as client:
        company = _visible_text(client.get("/utbildningsintyg-for-foretag").get_data(as_text=True))
        competence = _visible_text(client.get("/kompetensregister").get_data(as_text=True))
        storage = _visible_text(
            client.get("/lagra-utbildningsintyg-digitalt").get_data(as_text=True)
        )
        sharing = _visible_text(client.get("/dela-utbildningsintyg").get_data(as_text=True))
        gdpr = _visible_text(client.get("/gdpr-utbildningsintyg").get_data(as_text=True))

    assert "personen behöver godkänna förfrågan" in company.lower()
    assert "inte en fullständig hr-plattform" in competence.lower()
    assert "PDF, JPG eller PNG" in storage
    assert "50 MB" in storage
    assert "PDF-bilagor via e-post" in sharing
    assert "inte en offentlig länk eller QR-kod" in sharing
    assert "inte juridisk rådgivning" in gdpr.lower()
    assert "inte organisationen automatiskt GDPR-kompatibel" in gdpr


def test_homepage_links_to_all_guides(empty_db):
    with _client() as client:
        response = client.get("/")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert '<h2 id="home-guides-title">Guider och artiklar</h2>' in body
    for page in SEO_PAGES:
        assert f'href="{page["path"]}"' in body


def test_company_guide_ctas_open_the_company_application(empty_db):
    with _client() as client:
        response = client.get("/utbildningsintyg-for-foretag")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert body.count('href="/ansok/foretagskonto"') >= 2


# Copyright (c) Liam Suorsa and Mika Suorsa
