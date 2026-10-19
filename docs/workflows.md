<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# GitHub Actions och workflows

Det här är de workflows som finns i `.github/workflows` i dag.

## CI

`ci.yml`

- Kör på `push` och `pull_request`.
- Testar Python `3.10`, `3.11`, `3.12`, `3.13`, `3.14` och `3.15`.
- Pipenv och Docker använder Python `3.15`; äldre versioner finns kvar i CI för kompatibilitetskontroll.
- Installerar beroenden från `requirements.txt`.
- Kör `mypy app.py functions services`.
- Kör `pytest` utan coverage när `CODACY_PROJECT_TOKEN` saknas.
- Kör `pytest --cov=. --cov-report xml` och rapporterar till Codacy när token finns.

## Docker-bygge

`docker-image.yml`

- Kör på `push` och `pull_request` mot `main`.
- Bygger Compose-upplägget från `docker-compose.yml`.
- Använder `python:3.15.0-alpine3.24`. YARA kan byggas från källkod med tillfälliga byggverktyg som tas bort efter installationen.
- Kontrollerar paketberoenden, import av PostgreSQL-drivrutiner, en enkel YARA-regel och riktig PDF-skanning med Quicksand under bygget.
- Bygger psycopgs C-variant i samma version som `requirements.txt` mot systemets `libpq`. Bygget kontrollerar att C-varianten fungerar efter att byggverktygen tagits bort på Alpine.
- Har `DEV_MODE=false` som standard.
- Har två byggsteg men båda använder samma Compose-fil i nuvarande repo.

## Dependency review

`dependency-review.yml`

- Kör på `pull_request` mot `main`.
- Använder GitHubs dependency review action.
- Lägger sammanfattning som PR-kommentar.

## Bandit

`security-bandit.yml`

- Kör på `push`, `pull_request`, `workflow_dispatch` och `workflow_call`.
- Installerar Bandit.
- Kör:

```bash
bandit -r . -f json -o bandit.json --exit-zero
```

- Konverterar resultatet till SARIF och laddar upp till GitHub Security.

## CodeQL

`security-codeql.yml`

- Kör på `push`, `pull_request` mot `main` och veckoschema.
- Initierar CodeQL för Python.
- Kör `autobuild` och därefter analys.

## Legacy-wrapper-flöden

- `bandit.yml` - wrapper som anropar `security-bandit.yml`
- `security_scan.yml` - wrapper som anropar `security-bandit.yml`

De här två innehåller ingen egen analyslogik längre.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
