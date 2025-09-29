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

Alla PDF-intyg krypteras numera med AES-GCM där nycklarna härleds via PBKDF2 på samma sätt som övriga känsliga värden i applikationen. Spara hemligheterna i din permanenta `.env`-fil så att samma härledda nycklar används även efter en omstart. Du måste konfigurera miljövariabeln `PDF_ENCRYPTION_KEYS` med minst en hemlig fras (till exempel `primar-hemlighet`). Vid nyckelrotation lägger du till den nya frasen först i listan och behåller tidigare fraser efteråt:

```
PDF_ENCRYPTION_KEYS="<ny primär fras>,<gammal fras>"
```

Starta om applikationen efter att variabeln har uppdaterats så att den nya ordningen börjar användas. Systemet testar samtliga fraser i ordning när ett dokument dekrypteras, vilket gör att äldre filer fortsätter att vara läsbara tills du tar bort deras fraser från listan. Äldre dokument som tidigare krypterats med Fernet kan fortfarande dekrypteras så länge deras ursprungliga Fernet-nycklar finns kvar i variabeln.
