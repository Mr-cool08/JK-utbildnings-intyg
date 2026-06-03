<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# GitHub Actions och workflows

Det här är de workflows som finns i `.github/workflows` i dag.

## CI

`ci.yml`

- Kör på `push` och `pull_request`.
- Testar Python `3.10`, `3.11` och `3.12`.
- Installerar beroenden från `requirements.txt`.
- Kör `mypy app.py functions services status_service`.
- Kör `pytest` utan coverage när `CODACY_PROJECT_TOKEN` saknas.
- Kör `pytest --cov=. --cov-report xml` och rapporterar till Codacy när token finns.

## Docker-bygge

`docker-image.yml`

- Kör på `push` och `pull_request` mot `main`.
- Bygger Compose-upplägget från `docker-compose.yml`.
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
