# Loggnivåpolicy

Projektet använder följande konsekventa nivåmatris för loggning:

- `DEBUG`: Intern detaljinformation för felsökning och utveckling.
- `INFO`: Normal livscykel och förväntade driftflöden.
- `WARNING`: Återhämtningsbar avvikelse där körning kan fortsätta.
- `ERROR`: En operation misslyckades men tjänsten är fortsatt tillgänglig.
- `CRITICAL`: Tjänsten är otillgänglig eller dataintegritet/säkerhet hotas.

## Tillämpning

- Välj lägsta nivå som korrekt beskriver konsekvensen.
- Använd `CRITICAL` sparsamt, endast för allvarliga driftlägen.
- Använd `WARNING` för valideringsfel och andra avvikelser som hanteras kontrollerat.
- Undvik att logga känslig information; använd befintliga maskeringshjälpare.

<!-- Copyright (c) Liam Suorsa -->
