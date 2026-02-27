<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Utveckling

Snabb guide för lokal utveckling.

## Utan Docker

1. Installera paket:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Skapa `.env`:

```bash
cp .example.env .env
```

3. Slå på dev-läge:

```env
DEV_MODE=true
PORT=8080
```

4. Starta app:

```bash
python app.py
```

## Med Docker

```bash
docker compose up --build
```

## Tester

Försök först:

```bash
pytest -n auto
```

Annars:

```bash
pytest
```

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
