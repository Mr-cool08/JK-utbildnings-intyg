# Loggningsstilguide

Projektet loggar på svenska och loggarna ska vara tydliga utan att läcka känslig data.

## Grundregler

- Skriv på svenska.
- Skriv kort och konkret.
- Beskriv vad som hände, inte vad du hoppas ska ha hänt.
- Använd projektets loggningshjälpmedel i `functions.logging` i stället för att sprida egen root-loggning.

## Logga inte känslig data

Undvik att logga:

- fullständiga personnummer
- lösenord
- reset-token
- sessiondata
- oavkortade e-postadresser när maskering är möjlig

Projektet har tester som verifierar maskering i flera känsliga flöden.

## Bra loggstruktur

En bra loggrad innehåller ofta:

1. Händelse
2. Berörd resurs eller identifierare
3. Resultat
4. Felorsak om något misslyckades

## Bra verb

- Lyckat: `Sparade`, `Skickade`, `Uppdaterade`, `Raderade`, `Godkände`
- Varning: `Ogiltig`, `Avvisad`, `Saknas`, `Obehörig`
- Fel: `Misslyckades`, `Kunde inte`, `Fel uppstod`

## Exempel

- `logger.info("Sparade PDF med id %s", pdf_id)`
- `logger.warning("Obehörigt admin-anrop mot %s", request.path)`
- `logger.error("Misslyckades att dela PDF %s", pdf_id)`

## Relaterade tester

- `tests/test_logging_masking.py`
- `tests/test_logging_utils_additional.py`

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
