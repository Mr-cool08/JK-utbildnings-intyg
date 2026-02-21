# Loggningsstilguide

Denna guide beskriver hur loggmeddelanden ska skrivas i projektet.

## Språk
- Loggar skrivs på **svenska**.
- Använd tydliga och konkreta formuleringar.
- Undvik blandning av svenska och engelska i samma meddelande.

## Ton
- Skriv sakligt, kort och handlingsbart.
- Beskriv vad som hände och gärna varför, utan skuldformuleringar.
- Använd konsekvent tempus i presens, till exempel "Misslyckades med att spara" eller "Använder lokal databas".

## Fältordning i strukturerad loggning
När parametrar skickas till loggern ska ordningen vara:
1. **Händelsebeskrivning** (fast text)
2. **Resurs/id** (t.ex. pdf_id, person_hash)
3. **Aktör** (t.ex. admin, handledare)
4. **Teknisk detalj/fel** (vid behov)

Exempel:
- `logger.info("Sparade PDF för %s med id %s", mask_hash(pnr_hash), pdf_id)`
- `logger.warning("Obehörigt admin-GET-anrop")`
- `logger.error("Misslyckades med att dela pdf %s från %s till %s. Fel: %s", pdf_id, avsandare, mottagare, exc)`

## Verb och ordval
Använd dessa verb konsekvent:
- **Lyckade flöden:** "Sparade", "Skickade", "Hämtade", "Uppdaterade", "Raderade", "Loggade in".
- **Varningar/fel:** "Ogiltig", "Obehörig", "Misslyckades", "Kunde inte", "Saknas".
- **Systemtillstånd:** "Aktiverad", "Inaktiverad", "Använder", "Initierar".

Undvik engelska standardord i loggtext som:
- "Invalid", "Failed", "Unauthorized", "Stored", "Using".

<!-- Copyright (c) Liam Suorsa -->
