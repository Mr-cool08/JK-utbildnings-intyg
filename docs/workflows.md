# GitHub Actions-arbetsflöden

Den här dokumentationen beskriver hur våra arbetsflöden i `.github/workflows` är tänkta att användas.

## CI

**Fil:** `.github/workflows/ci.yml`

**Syfte:** Köra testsviten via `pytest` för att verifiera ändringar.

**När körs den?**
- Vid `push` till valfri branch.
- Vid `pull_request`.

**Python-versioner**
- 3.10
- 3.11
- 3.12

## Säkerhet: Bandit

**Fil:** `.github/workflows/security-bandit.yml`

**Syfte:** Statisk säkerhetsanalys för Python med Bandit och uppladdning av SARIF till Code Scanning.

**När körs den?**
- Vid `push` till `main`.
- Vid `pull_request` mot `main`.
- Manuell körning via `workflow_dispatch`.

**Hur fungerar den?**
- Kör Bandit med JSON-utdata (`--exit-zero`) och konverterar resultatet till SARIF innan uppladdning.

## Legacy-flöden för kompatibilitet

**Filer:**
- `.github/workflows/bandit.yml`
- `.github/workflows/security_scan.yml`

**Syfte:** Behåller tidigare workflow-namn så att Code Scanning kan koppla historiska resultat till befintliga konfigurationer.

**När körs de?**
- Endast manuellt (`workflow_dispatch`) eller via `workflow_call`.

## Säkerhet: CodeQL

**Fil:** `.github/workflows/security-codeql.yml`

**Syfte:** CodeQL-analys för Python med schemalagd säkerhetsskanning.

**När körs den?**
- Vid `push` till `main`.
- Vid `pull_request` mot `main`.
- Schema: måndagar 04:37 UTC.

## Dependency Review

**Fil:** `.github/workflows/dependency-review.yml`

**Syfte:** Granskar beroenden i pull requests för kända sårbarheter och kan kommentera en sammanfattning i PR:en.

**När körs den?**
- Vid `pull_request` mot `main`.
