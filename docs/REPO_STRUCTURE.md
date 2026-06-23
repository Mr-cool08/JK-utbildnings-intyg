<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Repo-struktur

Det här är den nuvarande huvudstrukturen i projektet.

## Roten

- `app.py` - tunt kompositionslager som skapar Flask-appen och behåller de publika importytorna.
- `wsgi.py` - WSGI-entrypoint för serverkörning.
- `config_loader.py` - inläsning av miljövariabler och konfigurationsfiler.
- `course_categories.py` - kategorier och etiketter för intyg.
- `docker-compose.yml` - gemensam Compose-fil för lokal körning och serverdrift.
- `Dockerfile` - image för huvudappen.
- `entrypoint.sh` - startlogik i containern.
- `.example.env` - rekommenderad grund för `.env`.
- `README.md`, `tests.md`, `admin.md` - övergripande projekt- och användardokumentation.

## Applikationskod

- `web/` - webblagret för Flask med bootstrap, hjälpfunktioner, felhantering och route-moduler per domän.
- `functions/` - affärslogik för användare, admin, organisationer, databas, säkerhet, loggning, e-post och PDF-lagring.
- `services/` - stödtjänster som PDF-skanning och hjälptjänster kring drift.

## Webbgränssnitt

- `templates/` - Jinja-mallar för publika sidor, dashboard, adminpanel och företagskonton.
- `static/` - CSS, JavaScript, bilder, `robots.txt` och `sitemap.xml`.

## Drift och verktyg

- `deploy/` - Traefik, MTA-STS, certifikatexempel, Fail2ban och rclone-relaterade filer.
- `scripts/` - drift- och underhållsskript, bland annat `manage_compose.py` och `update_app.py`.

## Test och dokumentation

- `tests/` - pytest-svit för funktion, regression, säkerhet, UI, prestanda och drift.
- `docs/` - teknisk dokumentation för utveckling, drift och säkerhet.
- `.github/workflows/` - CI-, Docker- och säkerhetsworkflows.

## Runtime-data

- `instance/` - lokal runtime-data som SQLite-filer i test- eller utvecklingsmiljö.
- `logs/` - loggfiler när appen eller tjänster körs lokalt.
- `.pytest_tmp*` - temporära pytest-kataloger som skapas vid testkörning.

## Extra noteringar

- `admin.md` används inte bara som dokumentation i repot utan renderas också inne i adminpanelen via `/admin/guide`.
- Projektet har i dagsläget ingen separat `docker-compose.prod.yml` i roten. Driftdokumentationen ska därför peka på `docker-compose.yml`.
- `docs/COMPATIBILITY_MATRIX.md` beskriver vilka publika importytor och startvägar som ska hållas stabila även när intern struktur rensas.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
