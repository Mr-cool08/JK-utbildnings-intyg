<!-- # Copyright (c) Liam Suorsa -->
## Rapportera en sårbarhet

Vi tar säkerhet på största allvar och uppskattar att du hjälper oss att skydda våra system och användare.

Om du upptäcker en sårbarhet, vänligen rapportera den till oss på följande sätt:

E-postadress: liam@utbildningsintyg.se

Beskrivning: Inkludera en så detaljerad beskrivning som möjligt, gärna med steg för att reproducera problemet.

Bilagor: Skärmdumpar, loggar eller proof-of-concept är välkomna för att underlätta felsökningen.

Vad du kan förvänta dig

Bedömning: Om sårbarheten accepteras kommer vi att påbörja åtgärdsarbetet och ge en uppskattad tidsram för fixen.

Avslag: Om sårbarheten inte accepteras förklarar vi varför, och om möjligt hänvisar vi till bästa praxis.

Vi ber att du:

Inte utnyttjar sårbarheten för annat än att verifiera dess existens.

Inte delar informationen offentligt förrän vi har hunnit åtgärda problemet.

Tillsammans kan vi skapa en tryggare digital miljö.

## Innehållssäkerhet (CSP)

Följande CSP-nivå ska vara standard i drift och utvecklingsmiljöer där Nginx används som reverse proxy:

- `default-src 'self'`
- `img-src 'self' data:`
- `style-src 'self' 'unsafe-inline'`
- `script-src 'self' https://www.googletagmanager.com https://cdn.consentmanager.net`
- `frame-ancestors 'none'`
- `base-uri 'self'`

### Varför policyn ser ut så här just nu

- `default-src 'self'` stänger standardmässigt all laddning från tredje part.
- `img-src 'self' data:` tillåter lokala bilder och data-URI:er som används i vissa UI-flöden.
- `style-src` behåller tillfälligt `'unsafe-inline'` eftersom delar av adminvyer använder inline-stilar i markup (t.ex. `style="display:none"`).
- `script-src` tillåter i första hand endast egna skript. Två externa domäner är explicit tillåtna för befintlig analys-/samtyckesintegration.
- `frame-ancestors 'none'` förhindrar klickkapning via inbäddning i iframe.
- `base-uri 'self'` förhindrar att angripare ändrar bas-URL för relativa länkar.

### Stegvis härdning framåt

1. Flytta kvarvarande inline-stilar i templates till CSS-filer.
2. När inline-stilar är borttagna: ta bort `'unsafe-inline'` från `style-src`.
3. Utvärdera om externa script-källor fortfarande behövs i alla miljöer.
4. Håll policyn identisk mellan staging och produktion för att undvika överraskningar vid release.

Vid ändring av CSP ska både Nginx-konfiguration och denna dokumentation uppdateras samtidigt.
