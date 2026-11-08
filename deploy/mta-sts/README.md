# MTA-STS

Här ligger policyfilen som appen publicerar för MTA-STS.

## Filplats i repo

- `deploy/mta-sts/.well-known/mta-sts.txt`

## Publik adress

Filen ska vara nåbar via:

`https://mta-sts.utbildningsintyg.se/.well-known/mta-sts.txt`

Policyn serveras av huvudappen. Domän- och TLS-routingen ligger centralt i [Traefik-repots `dynamic/utbildningsintyg.yml`](https://github.com/Mr-cool08/traefik/blob/main/dynamic/utbildningsintyg.yml), inte i appens `docker-compose.yml`.

## Kontrollera innan `mode: enforce`

1. DNS TXT för `_mta-sts.utbildningsintyg.se` finns och har rätt `id`.
2. DNS för `mta-sts.utbildningsintyg.se` pekar rätt.
3. TLS fungerar för den publicerade MTA-STS-domänen.
4. Policyn går att hämta från internet.
5. MX-värdar och certifikat matchar policyn.

Använd `mode: testing` tills allt är verifierat.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
