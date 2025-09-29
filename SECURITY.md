## Reporting a Vulnerability

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

## Kryptering av lagrade PDF:er

Alla PDF-intyg krypteras med Fernet innan de sparas i databasen. Du måste konfigurera miljövariabeln `PDF_ENCRYPTION_KEYS` med minst en giltig Fernet-nyckel (till exempel genererad via `python -m cryptography.fernet`). Vid nyckelrotation lägger du till den nya nyckeln först i listan och behåller tidigare nycklar efteråt:

```
PDF_ENCRYPTION_KEYS="<ny primär nyckel>,<gammal nyckel>"
```

Starta om applikationen efter att variabeln har uppdaterats så att den nya nyckelordningen börjar användas. Systemet testar samtliga nycklar i ordning när ett dokument dekrypteras, vilket gör att äldre filer fortsätter att vara läsbara tills du tar bort deras nycklar från listan.
