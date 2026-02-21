# Hur man administrerar systemet
#### Denna guide täcker de grundläggande uppgifterna för kontohantering, användarhantering och supportsystem.
---





## Inloggning
- För att logga in i administrationspanelen, navigera till `/admin` på utbildningsintyg.se. 

- För att få åtkomst till supporten måste du logga in på epostadressen `support@utbildningsintyg.se` 

- Inloggningsuppgifter tillhandahålls av systemadministratören[^D]. 



## Ansökningshantering
Användaren kan skapa en ansökan om att öppna ett konto genom att fylla i ett formulär med nödvändig information. Du som administratör kan granska och godkänna eller avvisa dessa ansökningar via administrationspanelen under **Ansökningar**


## Användarhantering
Administratören kan hantera användare genom att navigera till fliken **Användare** i administrationspanelen. Här kan du:
- Skapa nya användarkonton.
- Radera befintliga användarkonton.
- Återställa lösenord för användare.
- Verfiera intyg som laddats upp av användare.




### Kontotyper
- **Standardkonto**: Ger grundläggande åtkomst till utbildningsintygstjänster. såsom att ladda upp och hantera certifikat[^C].
- **Företagskonto**: Ger utökad åtkomst och funktioner såsom att hantera flera användare[^B].
- **Administratörskonto**: Ger full åtkomst till alla systemfunktioner inklusive användarhantering och systeminställningar[^A] .

## Fakturisering
Administratören kan se en Faktureringslista under fliken **Fakturering** i administrationspanelen. Här kan du granska och hantera alla fakturor som har skapats för företagskonton.


## Företagskonton
Under fliken **Företagskonton** kan administratören hantera alla företagskonton. Dessa funktioner inkluderar:
- Koppla företagskonto till användare
- Skapa nya företagskonton
- Visa kopplade användare för varje företagskonto

## Supporthantering
Supportärenden hanteras utanför administrationspanelen via e-post. Supportteamet kan nås på `support@utbildningsintyg.se` för att hjälpa användare med deras frågor och problem.

*inloggning för support är separat från administrationspanelen*.


## Säkerhet
Administratören ska följa dessa säkerhetsriktlinjer:
- Ge aldrig ut administratörslösenordet till obehöriga personer.
- Ge aldrig ut supportinloggningsuppgifter till obehöriga personer.
- Vid misstänkt aktivitet, informera omedelbart systemadministratören [^D].
- Vid systemkrash, ska administratören kontakta systemadministratören [^D] för återställning och felsökning. **Viktigt**: Försök inte att återställa systemet själv om du inte är utbildad för det.

### Noter
All administrativ hantering loggas för säkerhetsändamål och revision.


## Länkar
- [Utbildningsintyg.se](https://utbildningsintyg.se)
- [Support E-post](mailto:support@utbildningsintyg.se)
- [Administrationspanel](https://utbildningsintyg.se/admin)
- [Faktureringslista](https://utbildningsintyg.se/admin/fakturering)
- [Användarhantering](https://utbildningsintyg.se/admin/konton)
- [Hantering av företagskonton](https://utbildningsintyg.se/admin/foretagskonto)
- [Ansökningshantering](https://utbildningsintyg.se/admin/ansokningar)
- [Hantering av intyg](https://utbildningsintyg.se/admin/intyg)
- [Systemadministratör E-post](mailto:liam@utbildningsintyg.se)


## Error hantering
Vid fel i administrationspanelen, följ dessa steg:
1. Notera felmeddelandet som visas.
2. Ta en skärmdump av felet.
3. Notera vilka åtgärder som ledde till felet.
4. Notera ner systeminformation (webbläsare, version, operativsystem).
5. Notera ner **tidpunkten** för felet.
6. Skapa en "Issue" i vårat [GitHub repository](https://github.com/Mr-cool08/JK-utbildnings-intyg/issues) (Konto krävs)
7. Bifoga all information du samlat in i "Issue".



### Fotnoter
[^A]: Administratörskonto är endast för hantering av hela systemet.
[^B]: Företagskonto har en konstnad baserad på antalet användare som är kopplade till företagskontot.
[^C]: Standardkonto är gratis.
[^D]: Systemadministratören E-post: `liam@utbildningsintyg.se`

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
