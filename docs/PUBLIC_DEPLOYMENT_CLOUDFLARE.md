<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Publik drift med Cloudflare Tunnel

Utbildningsintyg använder en **gemensam Cloudflare Tunnel** som drivs i [infrastrukturprojektet](https://github.com/Mr-cool08/infrastruktur_JK). Ingen publik Traefik-container, eget origin-certifikat eller direkt exponerad webbport krävs i detta projekt.

## Förutsättningar

1. En fjärrhanterad tunnel i Cloudflare med en ansluten och frisk `cloudflared`-connector.
2. Ett befintligt externt Docker-nätverk `jk_tunnel_net` på samma Docker-värd. Skapa en gång vid behov: `docker network create jk_tunnel_net`.
3. Infrastrukturens `cloudflared` och denna applikations `app` ansluter båda till `jk_tunnel_net`.
4. Behåll nuvarande Compose-projektnamn, `.env`, PostgreSQL 16 och databasvolymer vid migrering.

## Cloudflare-rutter

Konfigurera de **publicerade applikationsrutterna** i Cloudflares dashboard för samma tunnel:

| Hostname | Service URL | Kommentar |
| --- | --- | --- |
| `utbildningsintyg.se` | `http://utbildningsintyg:80` | Huvuddomän |
| `www.utbildningsintyg.se` | `http://utbildningsintyg:80` | Alternativt kontrollerad redirect till huvuddomänen |
| `mta-sts.utbildningsintyg.se` | `http://utbildningsintyg:80` | Begränsa rutten till `/.well-known/mta-sts.txt` om den konfigureras med path-matchning |

MTA-STS-policyn serveras av Flask-appen på `/.well-known/mta-sts.txt`. Vid path-matchning ska andra sökvägar på MTA-STS-hostnamnet inte routas till appen. Testa att de returnerar 404; om dashboard-konfigurationen inte kan åstadkomma detta behövs kompletterande edge-regel eller separat begränsad routing.

Se till att DNS-posterna för hostnamnen är **Proxied** och pekar mot rätt tunnel; normalt hanterar Cloudflare DNS-posten när en publicerad tunnelrutt läggs till. Undvik gamla A/AAAA/CNAME-poster till tidigare origin eller tunnel.

## SSL och betrodda proxysteg

- **Besökare → Cloudflare:** HTTPS med Cloudflares hanterade edge-certifikat (kontrollera `SSL/TLS → Edge Certificates`).
- **Cloudflare → cloudflared:** krypterad Cloudflare Tunnel.
- **cloudflared → app:** intern HTTP via `jk_tunnel_net`; inget origin-certifikat behövs på denna Docker-värd.

I applikationens befintliga `.env`:

~~~env
TRUSTED_PROXY_COUNT=1
PREFERRED_URL_SCHEME=https
SESSION_COOKIE_SECURE=true
~~~

`TRUSTED_PROXY_COUNT` måste motsvara den faktiskt betrodda proxikedjan och verifieras mot riktiga HTTPS-anrop: korrekt klient-IP, schemat `https`, redirects och säkra cookies. Tillåt inte direkt offentlig åtkomst till appens HTTP-port. Om en annan reverse proxy introduceras ändras förutsättningarna.

## Nätverk och portar

`app` är ansluten till `jk_tunnel_net` med aliaset `utbildningsintyg`, samt privata `db_net`. PostgreSQL och backup använder bara `db_net`. Bakgrundsjobbet `expiry_reminder` använder `db_net` och ett separat `worker_net` för utgående SMTP. `dev_http` och `vscode` använder ett eget `dev_net`, inte tunnelnätet.

Ingen host-port publiceras för webbappen eller PostgreSQL. För lokal databasadministration:

~~~bash
docker compose exec postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
~~~

Använd inga `docker compose down -v` eller `docker volume prune` under migreringen. Databasvolymen har fortfarande namnet `jk-utbildnings-intyg_pgdata`.

## Start och verifiering

~~~bash
docker network inspect jk_tunnel_net
docker compose -f docker-compose.yml config --quiet
docker compose -f docker-compose.yml up -d --build
docker compose -f docker-compose.yml ps
docker compose -f docker-compose.yml exec -T app curl -fsS http://127.0.0.1:80/health
curl -fsSI https://utbildningsintyg.se/health
curl -fsSI https://www.utbildningsintyg.se/health
curl -fsSI https://mta-sts.utbildningsintyg.se/.well-known/mta-sts.txt
~~~

Testa även inloggning, filuppladdning, e-postutskick, säkerhetsheaders, HTTP→HTTPS och att MTA-STS-hostnamnet inte exponerar övriga appvägar. Tidigare Traefik-middlewares för säkerhetsheaders och uppladdningsstorlek måste ersättas med lämpliga app- eller Cloudflare-regler; de följer **inte** automatiskt med en tunnel.

## Brandvägg och säkerhet

Tunneln kräver utgående åtkomst till Cloudflare, inte öppna inkommande 80/443. Behåll endast nödvändiga host-tjänster och SSH. Projektets äldre `scripts/firewall/cloudflare-ufw.sh` är framtaget för en origin som kan nås direkt; **kör det inte automatiskt som en del av tunnelmigreringen**. Granska aktiva brandväggsregler och säkerställ att SSH fortfarande fungerar.

## Felsökning

- **1033:** kontrollera att domänens DNS-post pekar på den aktiva tunneln samt att `cloudflared` är ansluten.
- **502:** kontrollera att `cloudflared` och `app` delar `jk_tunnel_net`, att aliaset `utbildningsintyg` finns och att appen lyssnar på port 80.
- **Felaktiga HTTP-redirects/cookies:** granska `TRUSTED_PROXY_COUNT`, `PREFERRED_URL_SCHEME`, `SESSION_COOKIE_SECURE` och proxyheaders.
- **MTA-STS:** verifiera separat DNS, certifikat och exakt sökväg för MTA-STS.

Se [migrering och rollback](DEPLOYMENT.md#säker-migrering-till-cloudflare-tunnel).

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
