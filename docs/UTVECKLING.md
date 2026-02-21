<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Utveckling

Den här guiden beskriver hur du kör applikationen lokalt med eller utan Docker.

## Förutsättningar

- Python 3.12
- Git
- (Valfritt) Docker + Docker Compose för containerbaserad utveckling

## Utveckling utan Docker

1. **Skapa virtuell miljö och installera beroenden**
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
   På Windows räcker `pip install -r requirements.txt` eftersom beroendefilen redan använder binära hjul för PostgreSQL.
2. **Skapa lokal konfiguration**
   ```bash
   cp .example.env .env
   ```
3. **Aktivera utvecklingsläge**
   Lägg till eller uppdatera följande i `.env`:
   ```env
   DEV_MODE=True
   PORT=8080
   ```
   `DEV_MODE` aktiverar Flask-debuggning, lokal SQLite samt mer detaljerade loggar. Demoläge styrs separat via `ENABLE_DEMO_MODE`.
4. **Starta applikationen**
   ```bash
   python app.py
   ```
   Appen svarar på <http://localhost:8080>.

## Utveckling med Docker Compose

Docker-stacken för utveckling finns i `docker-compose.yml` och kör applikationen med en lokal PostgreSQL-container.

1. **Skapa en lokal miljöfil**
   ```bash
   cp .example.env dev_stack.env
   ```
   Uppdatera `dev_stack.env` med korrekta värden för `POSTGRES_*` och övriga inställningar.
2. **Starta stacken**
   ```bash
   docker compose up --build
   ```

### Lokala URL:er

- Appen: <http://localhost:8080>
- Demoapp: <http://localhost:8081>
- Statussida: <http://localhost:8082>

## Tester

Kör hela testsviten med:

```bash
pytest
```
