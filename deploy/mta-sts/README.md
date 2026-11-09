# MTA-STS

Här ligger policyfilen som appen publicerar för MTA-STS.

## Filplats i repo

- `deploy/mta-sts/.well-known/mta-sts.txt`

## Publik adress

Filen ska vara nåbar via:

`https://mta-sts.utbildningsintyg.se/.well-known/mta-sts.txt`

Policyn serveras av huvudappen på `/.well-known/mta-sts.txt`. HTTPS och hostname-routning hanteras via den [gemensamma Cloudflare Tunnel-infrastrukturen](https://github.com/Mr-cool08/infrastruktur_JK), inte i appens `docker-compose.yml`. Skapa en publicerad tunnelrutt för `mta-sts.utbildningsintyg.se` mot `http://utbildningsintyg:80`, helst begränsad till just policyfilens sökväg. Andra sökvägar på MTA-STS-hostnamnet ska inte exponera webbappen; kontrollera 404.

## Kontrollera innan `mode: enforce`

1. DNS TXT för `_mta-sts.utbildningsintyg.se` finns och har rätt `id`.
2. DNS för `mta-sts.utbildningsintyg.se` pekar rätt.
3. TLS fungerar för den publicerade MTA-STS-domänen.
4. Policyn går att hämta från internet.
5. MX-värdar och certifikat matchar policyn.

Använd `mode: testing` tills allt är verifierat.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
