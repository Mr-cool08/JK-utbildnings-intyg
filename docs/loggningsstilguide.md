# Loggningsstilguide

Skriv loggar enkelt och tydligt.

## Regler

- Skriv på svenska.
- Skriv korta meningar.
- Beskriv vad som hände.

## Bra verb

- Lyckat: `Sparade`, `Skickade`, `Uppdaterade`, `Raderade`.
- Fel: `Misslyckades`, `Ogiltig`, `Obehörig`, `Saknas`.

## Enkel struktur

1. Händelse
2. ID eller resurs
3. Vem som gjorde det
4. Felinfo (om det finns)

Exempel:
- `logger.info("Sparade PDF med id %s", pdf_id)`
- `logger.warning("Obehörigt anrop")`
- `logger.error("Misslyckades att dela PDF %s", pdf_id)`

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
