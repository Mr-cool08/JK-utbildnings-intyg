<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Kompatibilitetsmatris

Det här dokumentet fryser de ytor som ska hållas stabila medan repot städas internt.

## Importytor

- `app.py` ska fortsätta exportera `app`, `create_app` och `save_pdf_for_user`.
- `wsgi.py` ska fortsatt kunna exponera `app` för WSGI-servrar.
- Tester ska fortsatt kunna importera `app`, `functions`, `email_service`, `pdf` och `sec` via `app.py`.

## Startvägar

- Lokal start: `python app.py`
- Alternativ lokal start: `python wsgi.py`
- Docker-start: `docker compose up --build`

## Webbytor

- Samma URL:er, HTTP-metoder och endpointnamn ska bevaras.
- Samma template-namn och sessionnycklar ska bevaras.
- Samma användartexter på svenska ska bevaras om inte en uttrycklig ändring beställs.

## Intern struktur

- `app.py` får vara tunn, men den publika ytan ovan får inte brytas.
- `web/` är den nya interna platsen för bootstrap, route-registrering, felhantering och webbhjälpare.
- `functions/` och `services/` fortsätter vara ägare av affärslogik och stödtjänster.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
