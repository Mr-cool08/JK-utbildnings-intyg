<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Struktur för JK Utbildningsintyg

Den här filen beskriver hur repositoryt är organiserat och var nya filer bör placeras framöver.

## Katalogöversikt

- `app.py`, `wsgi.py` – Flask-applikationen och WSGI-entrypoint.
- `services/`, `templates/`, `static/` – Affärslogik, vyer och statiska resurser.
- `scripts/` – Drifts- och underhållsskript. Lägg manuella hjälpskript här i stället för i rotkatalogen.
- `docs/` – Dokumentation, installationsguider och driftinstruktioner.
- `deploy/`, `docker-compose*.yml`, `Dockerfile` – Container- och orkestreringsfiler.
- `tests/` – Testsvit som körs med `pytest`.
- `demo_assets/` – Exempel-PDF:er för demomiljön.
- `logs/` (skapas vid körning) – Körloggar som skrivs av applikationen eller Docker.

## Riktlinjer framåt

- **Dokumentation**: Nya guider och runbookar placeras i `docs/`. Länka från `README.md` om de är centrala.
- **Skript**: Bash- och Python-skript som inte körs som del av applikationen ska bo i `scripts/`. Håll namnen i `snake_case`.
- **Konfiguration**: Miljöfiler (`.env`) och exempel ska ligga i rotkatalogen eller under `deploy/` om de hör till containerkonfigurationen.
- **Tillgångar**: Statiska filer för demo/test läggs under `demo_assets/` eller `static/` beroende på användning.
- **Tester**: Lägg nya tester i `tests/` och kör `pytest` innan förändringar pushas.

Med den här strukturen blir det lättare att hitta dokumentation, hålla isär kod och drift, samt hålla rotkatalogen ren från tillfälliga filer.
