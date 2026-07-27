# Extern provisionering av privatkonto

Det här dokumentet beskriver integrations- och driftkontraktet för den
implementerade v1-endpointen:

```text
POST /api/external/private-account-provisioning
```

Endpointen är avsedd för server-till-server-anrop över HTTPS. Den tar emot ett
utbildningsintyg som PDF, kopplar det till ett privatkonto och skickar vid behov
ett e-postmeddelande med en aktiveringslänk.

Endast denna route finns under `/api/external/`. Andra externa routes, andra
HTTP-metoder och `OPTIONS` avvisas med JSON-svar. När integrationen är
avstängd finns routen kvar tekniskt men svarar med `404 external_route_not_found`.

## Affärsbeteende

Kontot matchas alltid först på normaliserat personnummer.

| Befintligt läge | Beteende |
| --- | --- |
| Inget privatkonto | Ett väntande privatkonto skapas, PDF:en lagras och ett aktiveringsmejl skickas. |
| Väntande privatkonto | Namn och e-post uppdateras efter konfliktkontroll. En ny aktiveringstoken skapas. |
| Aktivt privatkonto | Kontot och dess e-post ändras inte. PDF:en kopplas till det aktiva kontot. |
| Aktivt konto med användbar lagrad e-post | Mejl med PDF-bilaga skickas till den lagrade adressen. |
| Aktivt konto med äldre e-posthash som inte matchar inkommande e-post | Inkommande e-post ignoreras och inget mejl skickas. Svaret får `mail_status: "not_required"`. |
| Företagskopplat privatkonto eller e-post som hör till otillåten kontotyp | Begäran avvisas med `409 account_type_not_allowed`. |
| Samma PDF-hash finns redan för personnumret | Begäran avvisas med `409 document_already_exists`. |

En aktiv användares inkommande `name` eller `email` får alltså aldrig användas
för att skriva över kontouppgifterna.

## HTTP-kontrakt

Begäran måste ha `Content-Type: multipart/form-data` med en automatiskt
genererad boundary. Alla headers och multipartfält nedan måste förekomma exakt
en gång. Okända, dubbla eller felplacerade fält avvisas.

### Headers

| Header | Format |
| --- | --- |
| `X-External-Key-Id` | Aktivt nyckel-ID. 1–128 tecken; första tecknet alfanumeriskt, därefter även `.`, `_` och `-`. |
| `X-External-Timestamp` | Unix-tid i hela sekunder. Standardfönster är ±300 sekunder. |
| `X-External-Nonce` | Unikt per `key_id`, 16–128 tecken. Första tecknet ska vara alfanumeriskt; därefter tillåts även `.`, `_`, `~` och `-`. |
| `Idempotency-Key` | 8–200 synliga ASCII-tecken utan blanksteg. Ska identifiera en logisk verksamhetsbegäran. |
| `X-External-Pdf-Sha256` | 64 hextecken för SHA-256 av exakt de PDF-byte som skickas. |
| `X-External-Signature` | HMAC-SHA256 som 64 hextecken. Prefixet `sha256=` accepteras men behövs inte. |

Duplicerade headers får inte slås ihop med kommatecken av klient eller proxy.
Servern tolkar ett kommatecken i någon av de obligatoriska headervärdena som en
duplicerad header.

### Multipartfält

| Fält | Krav |
| --- | --- |
| `personal_identity_number` | Svenskt personnummer. I normaliseringen tas alla icke-siffror bort; 12 siffror kortas till de sista 10 och resultatet måste vara exakt 10 siffror. |
| `email` | Giltig e-postadress. Inledande och avslutande blanksteg tas bort och adressen konverteras till gemener. |
| `name` | Obligatoriskt namn, högst 200 tecken. Sammanhängande blanksteg normaliseras till ett enkelt mellanslag. |
| `expires_at` | Fältet är obligatoriskt men värdet får vara tomt. Ett angivet värde ska vara ett ISO-datum i formatet `ÅÅÅÅ-MM-DD`. |
| `category` | Exakt en giltig kategori-slug från `course_categories.py`. Värdet trimmas och konverteras till gemener. |
| `pdf` | Exakt en fil med filändelsen `.pdf` och MIME-typen `application/pdf`. |

PDF-innehållet måste:

- börja med bytesekvensen `%PDF-`;
- rymmas inom `EXTERNAL_PROVISIONING_MAX_PDF_BYTES`;
- ha samma SHA-256 som `X-External-Pdf-Sha256`;
- godkännas av Quicksand-skannern.

Den integrationsspecifika standardgränsen är 10 MiB. Flasks globala
uppladdningsgräns är 50 MB, men den externa gränsen får som mest sättas till
49 MiB (51 380 224 byte).

## Fingerprint och HMAC-signatur

Signeringen görs i två steg: först en fingerprint av de normaliserade
verksamhetsfälten, sedan HMAC över requestmetadata och fingerprinten.

### 1. Normalisera verksamhetsfälten

Bygg följande JSON-objekt:

```json
{
  "category": "heta-arbeten",
  "email": "anna@example.com",
  "expires_at": "2030-12-31",
  "name": "Anna Andersson",
  "pdf_sha256": "64-teckens-hexhash",
  "personal_identity_number": "9001011234"
}
```

Serialisera objektet som UTF-8 med:

- nycklar i alfabetisk ordning;
- inga blanksteg mellan nycklar och värden;
- Unicode-tecken som UTF-8, inte ASCII-escape;
- ingen avslutande radbrytning.

Python-motsvarigheten är:

```python
canonical_json = json.dumps(
    business_fields,
    ensure_ascii=False,
    separators=(",", ":"),
    sort_keys=True,
)
request_fingerprint = hashlib.sha256(
    canonical_json.encode("utf-8")
).hexdigest()
```

Timestamp, nonce, idempotency-nyckel, signatur, PDF-filnamn och MIME-typ ingår
inte i fingerprinten.

### 2. Bygg den kanoniska signatursträngen

Sammanfoga exakt dessa sju rader med `\n`, utan avslutande radbrytning:

```text
POST
/api/external/private-account-provisioning
<key_id>
<unix_timestamp>
<nonce>
<idempotency_key>
<request_fingerprint>
```

Beräkna sedan:

```text
hex(HMAC-SHA256(UTF8(secret), UTF8(canonical_signature_payload)))
```

Servern trimmar obligatoriska headervärden före kanoniseringen och jämför
signaturen med konstanttidsjämförelse. HMAC-hemligheten läses som UTF-8-byte.

### Referensexempel i Python

Exemplet använder redan normaliserade verksamhetsvärden. Klienten ansvarar för
att dess normalisering ger exakt samma resultat som reglerna ovan.

```python
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from uuid import uuid4

import requests


route = "/api/external/private-account-provisioning"
base_url = "https://utbildningsintyg.se"
key_id = "partner-v1"
secret = os.environ["PARTNER_HMAC_SECRET"].encode("utf-8")
pdf_path = Path("utbildningsintyg.pdf")
pdf_bytes = pdf_path.read_bytes()
pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()

form = {
    "personal_identity_number": "9001011234",
    "email": "anna@example.com",
    "name": "Anna Andersson",
    "expires_at": "2030-12-31",
    "category": "heta-arbeten",
}
business_fields = {
    "category": form["category"],
    "email": form["email"],
    "expires_at": form["expires_at"],
    "name": form["name"],
    "pdf_sha256": pdf_sha256,
    "personal_identity_number": form["personal_identity_number"],
}
canonical_json = json.dumps(
    business_fields,
    ensure_ascii=False,
    separators=(",", ":"),
    sort_keys=True,
)
fingerprint = hashlib.sha256(
    canonical_json.encode("utf-8")
).hexdigest()

timestamp = str(int(time.time()))
nonce = f"n-{secrets.token_urlsafe(24)}"
idempotency_key = f"provision-{uuid4().hex}"
signature_payload = "\n".join(
    (
        "POST",
        route,
        key_id,
        timestamp,
        nonce,
        idempotency_key,
        fingerprint,
    )
)
signature = hmac.new(
    secret,
    signature_payload.encode("utf-8"),
    hashlib.sha256,
).hexdigest()

response = requests.post(
    f"{base_url}{route}",
    data=form,
    files={
        "pdf": (
            pdf_path.name,
            pdf_bytes,
            "application/pdf",
        )
    },
    headers={
        "X-External-Key-Id": key_id,
        "X-External-Timestamp": timestamp,
        "X-External-Nonce": nonce,
        "Idempotency-Key": idempotency_key,
        "X-External-Pdf-Sha256": pdf_sha256,
        "X-External-Signature": signature,
    },
    timeout=120,
)
print(response.status_code, response.json())
```

Skriv aldrig HMAC-hemligheten, nonce, idempotency-nyckeln eller signaturen till
klientens loggar.

## Svar

Alla svar under `/api/external/` är JSON och har:

```http
Cache-Control: no-store
Content-Type: application/json; charset=utf-8
```

Varje body innehåller minst:

```json
{
  "status": "success eller error",
  "code": "stabil_maskinkod",
  "message": "svensk beskrivning"
}
```

Ett lyckat svar är `201`:

```json
{
  "account_state": "pending",
  "code": "provisioning_completed",
  "mail_status": "sent",
  "message": "Privatkontot och PDF-dokumentet har behandlats.",
  "status": "success"
}
```

`account_state` är `pending` eller `active`. `mail_status` är normalt `sent`
eller `not_required`.

### Statuskoder och retrybeslut

| HTTP | Vanliga `code` | Klientåtgärd |
| --- | --- | --- |
| `201` | `provisioning_completed` | Terminalt lyckat resultat. Skicka inte på nytt. |
| `400` | `missing_header`, `duplicate_header`, `missing_field`, `duplicate_field`, `unknown_field`, `invalid_*`, `pdf_hash_mismatch`, `pdf_rejected`, `bad_request` | Korrigera kontraktsfelet. Använd ny nonce och normalt en ny idempotency-nyckel för den korrigerade verksamhetsbegäran. |
| `401` | `unknown_key_id`, `invalid_signature`, `timestamp_outside_window`, `unauthorized` | Korrigera nyckel, klocka eller signatur. Signera om med ny timestamp och nonce. |
| `404` | `external_route_not_found` | Kontrollera URL och att integrationen är aktiverad. |
| `405` | `method_not_allowed` | Använd `POST`. Endpointen erbjuder inte ett separat `OPTIONS`-kontrakt. |
| `409` | `nonce_reused` | Skicka samma logiska begäran med ny nonce, ny timestamp och ny signatur. |
| `409` | `idempotency_key_reused` | Nytt innehåll får inte använda samma idempotency-nyckel. Skapa en ny nyckel. |
| `409` | `document_already_exists`, `email_conflict`, `account_state_conflict`, `account_type_not_allowed`, `pending_account_missing`, `active_account_missing`, `active_email_unavailable`, `provisioning_conflict` | Terminal verksamhetskonflikt. Utred eller korrigera källdatan; gör inte blind retry. |
| `409` | `delivery_unknown` | Terminalt osäkert leveransläge. Skicka inte automatiskt igen. Hantera manuellt enligt avsnittet om SMTP. |
| `413` | `pdf_too_large` | Minska PDF-filen. |
| `415` | `unsupported_media_type`, `unsupported_pdf_filename`, `unsupported_pdf_mime`, `invalid_pdf` | Korrigera multipart- eller PDF-formatet. |
| `425` | `request_in_progress` | Vänta med exponentiell backoff och försök igen med samma idempotency-nyckel men ny timestamp, nonce och signatur. |
| `429` | `rate_limit_exceeded` | Vänta med backoff. Svaret innehåller i nuläget ingen garanterad `Retry-After`. |
| `500` | `mail_delivery_failed` | Säker automatisk retry med samma idempotency-nyckel. Endast e-poststeget körs om. |
| `500` | `pdf_scanner_timeout`, `pdf_scanner_unavailable`, `pdf_scanner_error`, `database_temporarily_unavailable`, `internal_error` | Tillfälligt serverfel. Retry med samma idempotency-nyckel och ny signerad request är avsedd att vara säker. |
| `500` | `external_configuration_error`, `idempotency_state_missing`, `stored_document_missing`, `invalid_request_state` | Operatör måste först rätta serverläget eller utreda den sparade requestposten. |

## Idempotens, nonce och state machine

Idempotens gäller per kombination av `key_id` och `Idempotency-Key`.
Idempotency-nyckeln lagras HMAC-hashad. Request-fingerprint måste vara identisk
för alla försök med samma nyckel.

Viktigt för varje replay eller retry:

1. Behåll samma `key_id`, `Idempotency-Key`, normaliserade verksamhetsfält och
   PDF-hash.
2. Skicka hela multipartkontraktet igen.
3. Skapa en ny nonce.
4. Skapa en aktuell Unix-timestamp.
5. Beräkna en ny signatur.

En nonce registreras innan idempotency-posten hämtas. En terminal replay med
samma nonce avvisas därför som `nonce_reused`; idempotens innebär inte att
nonce får återanvändas.

De beständiga requesttillstånden är:

| Tillstånd | Betydelse |
| --- | --- |
| `processing` | Requesten är låst för validering, PDF-skanning eller lagring. |
| `stored_mail_pending` | Konto och PDF är committade; e-post återstår. |
| `mail_sending` | SMTP-anropet pågår eller kan ha påbörjats. |
| `mail_failed_retryable` | SMTP har entydigt inte skickat; samma idempotency-nyckel får återuppta endast mejlsteget. |
| `delivery_unknown` | SMTP kan ha accepterat meddelandet. Terminalt läge utan automatisk omsändning. |
| `completed` | Terminalt lyckat resultat. |
| `failed_terminal` | Terminalt fel vars sparade HTTP-status och body returneras vid replay. |

En terminal replay med samma fingerprint returnerar samma sparade HTTP-status
och body utan att skapa konto, PDF eller mejl igen. Samma idempotency-nyckel med
en annan fingerprint returnerar `409 idempotency_key_reused`.

En färsk `processing`, `stored_mail_pending` eller `mail_sending` ger `425`.
Efter `EXTERNAL_PROVISIONING_LOCK_TIMEOUT_SECONDS`, eller direkt om
`locked_at` saknas, kan en retry atomiskt ta över `processing` eller
`stored_mail_pending`. Ett gammalt `mail_sending` tas inte över för automatisk
omsändning utan övergår till `delivery_unknown`.

Vid retry från `mail_failed_retryable`:

- konto och PDF lagras inte igen;
- den lagrade PDF:en används;
- en väntande användare får en ny aktiveringstoken;
- föregående oanvänd token markeras som ersatt;
- `attempt_count` ökas.

## SMTP och osäkert leveransläge

PDF:en och kontot committas före SMTP-anropet. Ett mejlfel rullar därför inte
tillbaka lagringen.

SMTP-lagret skiljer mellan:

- **entydigt inte skickat**: anslutning eller autentisering misslyckades före
  sändning, eller SMTP avvisade mottagare/meddelande. API:t svarar
  `500 mail_delivery_failed` och kontrollerad retry är tillåten;
- **leverans okänd**: anslutningen bröts eller SMTP-fel inträffade efter att
  sändningen hade påbörjats. API:t svarar `409 delivery_unknown`;
- **bekräftat accepterat**: requesten avslutas som `completed`.

`delivery_unknown` får inte skickas om automatiskt. Operatören ska kontrollera
SMTP-logg, mottagarserver och eventuell leverans innan en manuell åtgärd görs.
Radera eller ändra inte request-, nonce- eller tokenposter för att tvinga en
retry. Om mejlet behöver återskapas ska det göras som en kontrollerad
supportåtgärd efter att risken för dubbelleverans har bedömts.

Alla utskicksförsök för samma idempotenta begäran återanvänder ett
deterministiskt logiskt `Message-ID` som bygger på den hashade
idempotency-identiteten. Det gör att ett kontrollerat mejlförsök kan
korreleras utan att den råa idempotency-nyckeln exponeras.

Port 465 använder SMTP över TLS. Övriga portar, normalt 587, använder STARTTLS.
Anslutningsetablering provas högst tre gånger. Quicksand kan använda upp till
55 sekunder, så Gunicorn- och klienttimeout bör lämna marginal; repots
entrypoint använder som standard `GUNICORN_TIMEOUT=120`.

## Aktiveringstoken

Ett nytt eller väntande privatkonto får ett mejl med en länk av formen:

```text
https://<publik-värd>/create_user/token/<rå-token>
```

Flödet är:

1. En kryptografiskt slumpad token skapas. Endast dess SHA-256-hash lagras.
2. Tidigare oanvända token för samma väntande konto markeras som ersatta.
3. Första giltiga `GET` växlar den råa token mot tokenhash i en kortlivad,
   signerad Flask-session.
4. Klienten får en `303`-redirect till den tokenfria URL:en
   `/create_user/token`.
5. Användaren anger och bekräftar ett lösenord på minst åtta tecken.
6. `POST` kräver giltig CSRF-token. Token tas atomiskt i anspråk, det väntande
   kontot flyttas till aktiva konton och övriga oanvända token återkallas.

Sessionen för tokenväxlingen gäller i 10 minuter. Själva tokenens giltighet
styrs av `EXTERNAL_PROVISIONING_ACTIVATION_TTL_HOURS`, som är 48 timmar som
standard. Använd, utgången, återkallad eller ersatt token kan inte aktivera ett
konto igen.

Aktiveringslänken byggs enbart från den betrodda `BASE_URL`, aldrig från den
inkommande requestens `Host`-header. När integrationen är aktiv måste
`BASE_URL` vara en publik HTTPS-adress utan sökväg, användaruppgifter,
query-parametrar eller fragment. I `DEV_MODE=true` tillåts även HTTP för lokal
utveckling.

Aktiveringssidor och redirects sätter:

```text
Cache-Control: no-store
Pragma: no-cache
Referrer-Policy: no-referrer
X-Robots-Tag: noindex, nofollow
```

Den råa token får aldrig loggas. Nuvarande deployment:

- maskerar `/create_user/token/<token>` i applikationsloggar;
- maskerar alla `X-External-*`-headers och `Idempotency-Key`;
- stänger av Traefiks accesslogg för tokenroutern;
- använder ett Gunicorn-accessformat som inte innehåller URL-sökvägen.

Behåll motsvarande skydd om reverse proxy, observability eller accessloggning
ändras. Sätt `SESSION_COOKIE_SECURE=true` i HTTPS-produktion och använd en stark,
beständig `secret_key`.

## Miljövariabler

### Integrationsspecifika variabler

| Variabel | Standard och beteende |
| --- | --- |
| `EXTERNAL_PRIVATE_PROVISIONING_ENABLED` | `false`. Sätt till `true` först när migration, HMAC, SMTP och skanner är verifierade. |
| `EXTERNAL_PROVISIONING_HMAC_KEYS` | Krävs när integrationen är aktiv. Rekommenderat format är ett JSON-objekt, exempelvis `{"partner-v1":"<minst-32-byte-hemlighet>"}`. Flera key ID stöds. |
| `EXTERNAL_PRIVATE_PROVISIONING_KEYS` | Äldre fallbacknamn som läses om huvudvariabeln saknas. Använd huvudvariabeln i ny konfiguration. |
| `EXTERNAL_PROVISIONING_MIN_SECRET_LENGTH` | `32`. Effektiv miniminivå kan aldrig sättas lägre än 32 UTF-8-byte. |
| `EXTERNAL_PROVISIONING_MAX_PDF_BYTES` | `10485760` (10 MiB). Måste vara större än 0 och högst 51 380 224 byte. |
| `EXTERNAL_PROVISIONING_LOCK_TIMEOUT_SECONDS` | `120`. Tid innan fastnad request kan tas över; effektivt minst 60 sekunder. |
| `EXTERNAL_PROVISIONING_ACTIVATION_TTL_HOURS` | `48`. Giltighetstid för ny aktiveringstoken; effektivt minst 1 timme. |
| `EXTERNAL_PROVISIONING_HASH_BACKFILL_BATCH_SIZE` | `25`. Migration 0023 begränsar värdet till intervallet 1–500. |

HMAC-konfigurationen accepterar även kommaseparerat
`key_id=hemlighet,key_id2=hemlighet2`, men JSON rekommenderas eftersom det ger
tydligare validering. Tomma, felaktiga eller dubbla key ID stoppar
produktionsstart när integrationen är aktiv.

Replay-skyddets tidsfönster är fast låst till ±300 sekunder och nonceposter
gäller i exakt 24 timmar. Dessa två säkerhetsgränser kan inte försvagas med
miljövariabler.

### Övrig nödvändig driftkonfiguration

| Variabel | Betydelse |
| --- | --- |
| `DEV_MODE` | Ska vara `false` i produktion. |
| `DISABLE_EMAILS` | Ska vara `false`. Aktiv integration tillsammans med `DISABLE_EMAILS=true` stoppar uppstart i produktion. |
| `smtp_server`, `smtp_port`, `smtp_user`, `smtp_password`, `smtp_from`, `smtp_timeout` | SMTP-inställningar. `smtp_from` faller tillbaka till `smtp_user`; standardport är 587 och standardtimeout 10 sekunder. |
| `BASE_URL` | Publik HTTPS-bas. Används bland annat för dashboardlänk och domändelen i `Message-ID`. |
| `DATABASE_URL` | Produktionsdatabas. PostgreSQL ska användas i drift. |
| `HASH_SALT` | Måste vara stark och beständig. Byte gör att befintliga personnummer- och äldre e-posthashar inte längre matchar. |
| `secret_key` | Stark, beständig Flask-nyckel för bland annat tokenfri aktiveringssession. |
| `SESSION_COOKIE_SECURE` | Ska vara `true` i produktion. Det är default när variabeln saknas och aktiv integration vägrar starta om värdet uttryckligen är falskt. |
| `TRUSTED_PROXY_COUNT` | Ska motsvara antalet betrodda proxyhopp så att externa aktiveringslänkar får rätt värd och schema. |
| `GUNICORN_TIMEOUT` | Standard i entrypoint är 120 sekunder. Ska ge marginal för PDF-skanning, databas och SMTP. |

Quicksand-binären måste finnas i runtime-miljön. Saknad binär, timeout eller
okänd exitstatus klassas som ett serverfel och PDF:en lagras inte.

I `DEV_MODE=true` får appen starta med `DISABLE_EMAILS=true`, men ett
provisioneringsutskick klassas då som `500 mail_delivery_failed` och aldrig som
ett lyckat mejl.

### Nyckelrotation

Rotera HMAC-nycklar genom att lägga till ett nytt `key_id`, inte genom att byta
hemlighet under ett befintligt ID:

1. Lägg till nytt `key_id` och behåll det gamla.
2. Distribuera konfigurationen och starta om tjänsten.
3. Flytta partnern till det nya ID:t.
4. Behåll det gamla ID:t tills inga requests eller säkra mejlretryer längre
   behöver signeras med det.
5. Ta därefter bort det gamla ID:t och starta om tjänsten.

Idempotency- och noncehashar härleds från respektive HMAC-hemlighet. Ett hemligt
värde får därför inte ändras under samma `key_id`.

## Migration 0023 i drift

Migrationen heter:

```text
0023_external_private_provisioning
```

Den körs automatiskt vid applikationsstart och:

- skapar `external_provisioning_requests`;
- skapar `external_provisioning_nonces`;
- skapar `private_account_activation_tokens`;
- lägger till nullable `content_sha256` på `user_pdfs`;
- backfillar SHA-256 i korta batchtransaktioner;
- inventerar befintliga PDF-dubbletter per personnummer och innehåll;
- behåller alla dubblettrader men lämnar icke-kanoniska kopior med
  `content_sha256 = NULL`;
- inför unikhet för `(personnummer, content_sha256)`;
- skapar unika constraints och sökindex för request-, nonce- och tokenflödena.

De tre säkerhetstabellerna är avsiktligt exkluderade från
`TABLE_REGISTRY` och ska inte exponeras i avancerad tabelladministration.

PostgreSQL använder advisory lock med namnet
`jk_utbildnings_intyg:schema_migrations` under hela flerfas-migreringen.
SQLite stöds för test och utveckling men är inte produktionsvalet.
Migreringsversionen registreras först när backfill och unikhetssteget är klart.
En avbruten körning kan därför startas om.

### Rekommenderad releaseordning

1. Ta en verifierad backup och genomför restore-test.
2. Testa migrationen på en aktuell kopia av produktionsdatabasen.
3. Lägg in HMAC-, SMTP-, `BASE_URL`-, databas- och cookieinställningar, men
   behåll `EXTERNAL_PRIVATE_PROVISIONING_ENABLED=false`.
4. Säkerställ att `HASH_SALT` är samma beständiga värde som den befintliga
   installationen.
5. Deploya och låt appstarten slutföra migration 0023. Vid flera repliker
   serialiserar PostgreSQL-låset migreringsjobbet.
6. Granska loggen efter dubblettinventering och migreringsfel.
7. Verifiera schema och migreringsversion.
8. Testa Quicksand, SMTP, publik HTTPS-länk och serverns tidssynkronisering.
9. Aktivera endpointen och starta om appen.
10. Kör smoke-test för nytt konto, aktivt konto, PDF-dubblett,
    `mail_delivery_failed` med retry och tokenaktivering.

Stora PDF-tabeller kan göra backfillen tidskrävande. Ett lägre
`EXTERNAL_PROVISIONING_HASH_BACKFILL_BATCH_SIZE` minskar tiden per transaktion
men ökar antalet transaktioner. Avbryt inte bara för att processen arbetar
länge; följ databas- och applikationslogg.

### Verifieringsfrågor för PostgreSQL

```sql
SELECT version, applied_at
FROM schema_migrations
WHERE version = '0023_external_private_provisioning';
```

```sql
SELECT
    COUNT(*) AS pdf_rader,
    COUNT(content_sha256) AS hashade_rader,
    COUNT(*) - COUNT(content_sha256) AS bevarade_legacy_dubbletter
FROM user_pdfs;
```

`NULL` efter en lyckad migration är tillåtet för bevarade historiska
dubbletter. Nya PDF-rader ska alltid få en hash.

```sql
SELECT state, mail_status, COUNT(*) AS antal
FROM external_provisioning_requests
GROUP BY state, mail_status
ORDER BY state, mail_status;
```

Kontrollera dessutom i databasens schemaverktyg att följande unikheter finns:

- `external_provisioning_requests (key_id, idempotency_key_hash)`;
- `external_provisioning_nonces (key_id, nonce_hash)`;
- `private_account_activation_tokens (token_hash)`;
- `user_pdfs (personnummer, content_sha256)`.

## Övervakning och incidenthantering

Följ minst:

- antal requests per `state` och `mail_status`;
- gamla `processing`, `stored_mail_pending` och `mail_sending`;
- `mail_failed_retryable` som väntar på partnerretry;
- varje `delivery_unknown`;
- avvisade signaturer, gamla timestamps och återanvända nonce;
- Quicksand-timeout och skannerfel;
- svarstid, SMTP-fel och databasconstraints;
- dubblettvarningar från migrationen.

Exempel för att hitta gamla lås, där intervallet ska motsvara den konfigurerade
lock-timeouten:

```sql
SELECT id, key_id, state, mail_status, attempt_count, locked_at, last_attempt_at
FROM external_provisioning_requests
WHERE state IN ('processing', 'stored_mail_pending', 'mail_sending')
  AND (locked_at IS NULL OR locked_at < NOW() - INTERVAL '120 seconds')
ORDER BY last_attempt_at;
```

För `processing` och `stored_mail_pending` är normal återhämtning att partnern
gör en korrekt idempotent retry. Ett gammalt `mail_sending` ska behandlas som
potentiellt levererat och får inte tvingas till automatisk omsändning.

Logga eller exportera aldrig rått personnummer, e-postadress, PDF-innehåll,
aktiveringstoken, HMAC-hemlighet, signatur, nonce eller idempotency-nyckel.
Även hashade identifierare och requesttabeller ska behandlas som känslig
driftdata.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
