# Flödesschema: Från kontoansökan till uppladdning av PDF

Nedan visas ett flöde för både **standardkonto** och **företagskonto**, från första förfrågan om konto till att en PDF laddas upp.

```mermaid
flowchart TD
    A[Förfrågan om konto tas emot] --> B{Välj kontotyp}
    A --> A1[Skicka e-post: Bekräftelse på mottagen förfrågan]

    B -->|Standardkonto| C[Användare fyller i personuppgifter]
    C --> C1[Skicka e-post: Bekräfta e-postadress]
    C1 --> D[Verifiering av e-post]
    D --> E[Granskning av grunduppgifter]
    E --> F{Godkänd?}
    F -->|Nej| G[Skicka e-post: Avslag med instruktioner]
    F -->|Ja| H[Skapa standardkonto]
    H --> H1[Skicka e-post: Konto aktiverat]
    H1 --> I[Användare loggar in]
    I --> J[Ladda upp PDF]
    J --> K[Validera filformat och filstorlek]
    K --> L{PDF giltig?}
    L -->|Nej| M[Visa felmeddelande och be om ny fil]
    M --> M1[Skicka e-post: Uppladdning misslyckades]
    L -->|Ja| N[Spara PDF och bekräfta uppladdning]
    N --> N1[Skicka e-post: PDF uppladdad]

    B -->|Företagskonto| O[Företagsrepresentant fyller i företagsuppgifter]
    O --> O1[Skicka e-post: Bekräfta e-postadress]
    O1 --> P[Verifiering av e-post och organisationsnummer]
    P --> Q[Administrativ granskning av företagsunderlag]
    Q --> R{Godkänd?}
    R -->|Nej| S[Skicka e-post: Avslag med kompletteringskrav]
    R -->|Ja| T[Skapa företagskonto]
    T --> T1[Skicka e-post: Företagskonto aktiverat]
    T1 --> U[Koppla användare till företagskonto]
    U --> U1[Skicka e-post: Användare kopplad till företagskonto]
    U1 --> V[Företagsanvändare loggar in]
    V --> W[Lägger till anställda]
    W --> X[Ladda upp PDF]
    X --> X1[Validera filformat, filstorlek och metadata]
    X1 --> Y{PDF giltig?}
    Y -->|Nej| Z[Visa felmeddelande och begär korrigering]
    Z --> Z1[Skicka e-post: Uppladdning kräver korrigering]
    Y -->|Ja| AA[Spara PDF, logga händelse och bekräfta uppladdning]
    AA --> AA1[Skicka e-post: PDF uppladdad]
```

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
