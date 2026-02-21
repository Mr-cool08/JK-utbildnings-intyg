# MTA-STS policyfil

Den här katalogen innehåller policyfilen som publiceras på:
`https://mta-sts.utbildningsintyg.se/.well-known/mta-sts.txt`.

## Driftnotering
- Nuvarande läge i policyfilen är `mode: testing` under verifieringsperiod.
- Sätt endast tillbaka till `mode: enforce` efter att följande är verifierat:
  1. DNS TXT för `_mta-sts.utbildningsintyg.se` är satt till `v=STSv1; id=<unik-identifierare>`.
  2. DNS A/CNAME för `mta-sts.utbildningsintyg.se` pekar mot rätt tjänst.
  3. TLS-certifikat och kompatibilitet är verifierat för berörda MX-värdar.
  4. Policyn är åtkomlig externt från flera nätverk och cache-ttl har passerat.

Copyright (c) Liam Suorsa and Mika Suorsa - Denna attribution gäller även för `deploy/mta-sts/.well-known/mta-sts.txt`.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
