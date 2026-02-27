<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# GitHub Actions (enkelt)

Här är arbetsflödena i `.github/workflows`.

- `ci.yml` – kör tester.
- `docker-image.yml` – bygger Docker-image.
- `security-bandit.yml` – kör Bandit och säkerhetsrapport.
- `security-codeql.yml` – kör CodeQL.
- `dependency-review.yml` – granskar beroenden i PR.
- `bandit.yml` och `security_scan.yml` – äldre kompatibilitetsflöden.

De flesta flöden körs vid push eller pull request mot `main`.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
