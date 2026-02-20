# Granskning av loggning och felhantering

## Övergripande bedömning
Nuvarande implementation har en bra grund med centrala hjälpfunktioner för loggning, maskering av känslig data och notifieringar. Samtidigt finns flera inkonsekvenser som gör beteendet svårt att förutse i produktion, särskilt kring loggnivåer, dubbelkonfiguration och tyst felhantering.

## Huvudfynd

### 1) Inkonsekvent loggkonfiguration mellan moduler
- Projektet har en central loggkonfiguration i `functions/logging/__init__.py`, men vissa moduler använder egna mönster.
- `status_service/app.py` kör `logging.basicConfig(...)` direkt istället för att använda samma struktur som resten av systemet.
- Flera moduler sätter egna nivåer (`DEBUG`, `INFO`) explicit efter `configure_module_logger`, vilket ger olika beteende beroende på importordning och miljö.

**Konsekvens:** Olikformig loggning mellan tjänster, svårare felsökning och risk för att viktigt brus eller viktig signal försvinner.

### 2) Risk för dubbla loggrader och svårstyrd handler-kedja
- `configure_module_logger` kopierar root-handlers in på varje modul-logger och sätter `propagate=False`.
- `_enable_debug_mode` adderar fler handlers direkt på root, `app.logger` och `functions.logger`, samt använder `print`.

**Konsekvens:** Risk för duplicerade rader, olika formattering i samma process, och blandning av standard output kontra loggsystem.

### 3) Inkonsekvent nivåklassning för återkommande driftfel
- I statuskontroller loggas många förväntade miljöproblem som `warning` (exempelvis saknade miljövariabler eller externa anslutningar som tillfälligt misslyckas).
- I andra delar används `exception` och `error` för liknande tillstånd.

**Konsekvens:** För många varningar i normal drift (alert fatigue) och svårare att särskilja allvarliga fel från degraderat läge.

### 4) Tyst felhantering ("swallowing") utan spårbarhet
- Flera ställen använder breda `except Exception` och ignorerar fel helt eller nästan helt.
- Exempel: email-handlern sväljer fel i `emit` utan fallback-loggning.
- Exempel: root-konfigurationen ignorerar fel vid koppling av email-handlern.

**Konsekvens:** Felsökning försvåras eftersom initierings- och notifieringsproblem inte blir synliga i loggarna.

### 5) Otydliga/mixade felmeddelanden och intern-exponering
- Projektet använder mestadels svenska meddelanden, men det finns en del engelska strängar i kritiska paths.
- Notifierings- och felmeddelandeflöden är delvis duplicerade i app-livscykeln (startup/shutdown/crash), med liknande `try/except`-block.

**Konsekvens:** Lägre konsekvens, mer underhållskostnad och risk för divergerande beteende vid framtida ändringar.

### 6) Potentiell notifierings-loop vid emailfel
- `EmailErrorHandler` skickar email för `ERROR`-nivå.
- Vid fel i `_send_email_async` loggas nytt `logger.error(...)` i samma modul.

**Konsekvens:** Vid vissa felbilder (t.ex. SMTP nere) kan detta ge återkommande error-kedjor och onödig belastning.

## Rekommenderade förbättringar (prioriterade)

### P0 – Snabbast värde / minskad drift-risk
1. **Inför en enhetlig loggpolicy per tjänst:**
   - Låt alla tjänster använda en gemensam konfigurationsfunktion (även `status_service`).
   - Avveckla `basicConfig` i tjänstekod.
2. **Stoppa potentiella notifieringsloopar:**
   - Lägg in en intern guard i email-notifiering så att fel i notifieringskanalen inte triggar samma kanal igen.
   - Alternativt: logga email-sändningsfel till separat logger/handler utan emailkoppling.
3. **Ersätt `print` i debug-flöde med logger:**
   - Behåll all diagnostik i samma pipeline.

### P1 – Konsistens och observability
4. **Standardisera loggnivåer med tydlig matris:**
   - `DEBUG`: interna detaljer.
   - `INFO`: normal livscykel/nyckelhändelser.
   - `WARNING`: återhämtningsbara avvikelser.
   - `ERROR`: operation misslyckades.
   - `CRITICAL`: tjänsten är sannolikt otillgänglig eller dataintegritet hotad.
5. **Byt breda `except Exception` där möjligt till specifika undantag.**
6. **Logga tyst felhantering minimalt med kontext:**
   - Om undantag måste sväljas, logga åtminstone en `debug`/`warning` med orsak och komponent.

### P2 – Underhållbarhet
7. **Extrahera gemensamma notifieringshjälpare för startup/shutdown/crash** för att minska duplicering.
8. **Rensa död kod/variabler** (exempelvis tidsstämpel som beräknas men inte används).
9. **Inför strukturerad loggning (JSON) i produktion** och korrelations-id för request-spårning mellan komponenter.

## Förslag på implementation i etapper
1. Etapp 1: Unified logging bootstrap + nivåmatris + borttag av `print`.
2. Etapp 2: Refaktorera notifieringsflöde och lägg loop-skydd.
3. Etapp 3: Smalna av exceptions och förbättra felmeddelanden.
4. Etapp 4: Introducera strukturerade loggar + request-id.

## Mätbara acceptanskriterier
- Ingen modul använder `logging.basicConfig` direkt.
- Inga dubbla loggrader för samma händelse i normal drift.
- Minst 90 % av `except Exception` ersatta med specifika undantag eller motiverad fallback.
- Fel i email-notifiering genererar högst en loggrad per incident och ingen kedjereaktion.
- Samma loggformat och tidszon i samtliga körbara tjänster.

<!-- Copyright (c) Liam Suorsa -->
