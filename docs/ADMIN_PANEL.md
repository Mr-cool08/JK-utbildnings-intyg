<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Adminpanelen

Det här dokumentet beskriver adminpanelen utifrån dagens routes, mallar och API:er.

## Översikt

Adminpanelen består i huvudsak av följande sidor:

- `/admin` - startsida för admin
- `/admin/guide` - renderar innehållet från `admin.md`
- `/admin/konton` - kontohantering
- `/admin/intyg` - uppladdade och kopplade intyg
- `/admin/foretagskonto` - företagskonton och användarkopplingar
- `/admin/ansokningar` - inkomna ansökningar
- `/admin/fakturering` - översikt för faktureringsunderlag
- `/admin/avancerat` - avancerad CRUD mot utvalda tabeller

## Ansökningar

Admin-API för ansökningar inkluderar bland annat:

- `GET /admin/api/ansokningar`
- `GET /admin/api/ansokningar/<id>`
- `POST /admin/api/ansokningar/<id>/godkann`
- `POST /admin/api/ansokningar/<id>/avslag`

Godkännande kan skapa aktiveringslänk både för standardkonto och företagskonto.

## Konton

Kontohanteringen stödjer bland annat:

- listning av aktiva och väntande konton
- uppdatering av kontouppgifter
- lösenordsstatus
- skapande av länk för att skapa lösenord
- återställning av lösenord
- borttagning av konto

Det finns även stöd för komplettering av äldre e-posthashar i admin-API:t.

## Intyg

Admin kan:

- ladda upp flera PDF:er samtidigt
- kräva kategori per uppladdning
- uppdatera kategorier
- ta bort felaktiga dokument

## Företagskonton

Admin-API:t för företagskonton stödjer:

- skapande av företagskonto
- koppling mellan organisationsnummer och användare
- översikt per organisationsnummer
- borttagning eller byte av koppling
- radering av företagskonto

## Avancerat läge

`/admin/avancerat` använder tabelladministration för utvalda tabeller och har endpoints för:

- schema
- listning av rader
- skapande av rad
- uppdatering av rad
- radering av rad

Det här läget är till för felsökning och kontrollerad administration, inte för vardaglig handläggning.

## Säkerhet

- Adminsidor kräver inloggning.
- Flera POST- och PUT-anrop kräver CSRF-token.
- Felaktiga eller obehöriga anrop loggas.
- Guiden i `/admin/guide` läser från `admin.md`, så den filen är en del av det faktiska gränssnittet.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
