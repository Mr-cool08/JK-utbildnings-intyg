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

Alla PDF-intyg krypteras nu med AES-GCM innan de sparas i databasen. Krypteringsnyckeln härleds via samma PBKDF2-baserade hashfunktion och `HASH_SALT` som används för att skydda lösenord, personnummer och e-postadresser. Säkerställ därför att `HASH_SALT` är satt i din `.env`-fil och håll värdet oförändrat så länge du behöver komma åt befintliga intyg.
