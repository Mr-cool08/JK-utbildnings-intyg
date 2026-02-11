# Flödesschema: Från kontoansökan till uppladdning av PDF

Nedan visas ett flöde för både **standardkonto** och **företagskonto**, från första förfrågan om konto till att en PDF laddas upp.

```mermaid
flowchart TD
    A[Förfrågan om konto tas emot] --> B{Välj kontotyp}

    B -->|Standardkonto| C[Användare fyller i personuppgifter]
    C --> D[Verifiering av e-post]
    D --> E[Granskning av grunduppgifter]
    E --> F{Godkänd?}
    F -->|Nej| G[Skicka avslag med instruktioner]
    F -->|Ja| H[Skapa standardkonto]
    H --> I[Användare loggar in]
    I --> J[Ladda upp PDF]
    J --> K[Validera filformat och filstorlek]
    K --> L{PDF giltig?}
    L -->|Nej| M[Visa felmeddelande och be om ny fil]
    L -->|Ja| N[Spara PDF och bekräfta uppladdning]

    B -->|Företagskonto| O[Företagsrepresentant fyller i företagsuppgifter]
    O --> P[Verifiering av e-post och organisationsnummer]
    P --> Q[Administrativ granskning av företagsunderlag]
    Q --> R{Godkänd?}
    R -->|Nej| S[Skicka avslag med kompletteringskrav]
    R -->|Ja| T[Skapa företagskonto]
    T --> U[Tilldela företagsroller och behörigheter]
    U --> V[Företagsanvändare loggar in]
    V --> W[Ladda upp PDF]
    W --> X[Validera filformat, filstorlek och metadata]
    X --> Y{PDF giltig?}
    Y -->|Nej| Z[Visa felmeddelande och begär korrigering]
    Y -->|Ja| AA[Spara PDF, logga händelse och bekräfta uppladdning]
```

<!-- Copyright (c) Liam Suorsa -->
