# MTA-STS

Här ligger policyfilen som appen publicerar för MTA-STS.

## Filplats i repo

- `deploy/mta-sts/.well-known/mta-sts.txt`

## Publik adress

Filen ska vara nåbar via:

`https://mta-sts.utbildningsintyg.se/.well-known/mta-sts.txt`

I nuvarande projekt routas den via huvudappen och Traefik-regler i `docker-compose.yml`.

## Kontrollera innan `mode: enforce`

1. DNS TXT för `_mta-sts.utbildningsintyg.se` finns och har rätt `id`.
2. DNS för `mta-sts.utbildningsintyg.se` pekar rätt.
3. TLS fungerar för den publicerade MTA-STS-domänen.
4. Policyn går att hämta från internet.
5. MX-värdar och certifikat matchar policyn.

Använd `mode: testing` tills allt är verifierat.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
