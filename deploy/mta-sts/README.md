# MTA-STS (enkel info)

Här ligger policyfilen för e-postsäkerhet.

Policyfilen publiceras på:
`https://mta-sts.utbildningsintyg.se/.well-known/mta-sts.txt`

## Innan du sätter `mode: enforce`

Kontrollera detta:

1. DNS TXT för `_mta-sts.utbildningsintyg.se` finns och har rätt `id`.
2. DNS för `mta-sts.utbildningsintyg.se` pekar rätt.
3. TLS-certifikat fungerar på aktuella MX-värdar.
4. Policyn går att nå från internet.

Använd `mode: testing` tills allt ovan är verifierat.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
