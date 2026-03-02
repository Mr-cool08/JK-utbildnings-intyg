# Migrerings- och refaktorplan: Option B (samlad `accounts`-modell)

## Antaganden
- Nuvarande databas använder SQLAlchemy-modeller i `functions/database.py` och affärslogik i `functions/applications.py`, `functions/users.py`, `functions/supervisors.py` samt ruttlogik i `app.py`.
- `application_requests` används redan som ett besluts-/ansökningsflöde och behöver bevaras som historik.
- Frontend förlitar sig på befintliga routes och payload-format för standardkonto och företagskonto.
- E-post används i praktiken som inloggningsidentifierare för aktiva konton.
- Eventuella skillnader mellan "supervisor" och "user" hanteras idag via tabellseparation och/eller route-val, inte via robust rollmodell.

## A) Architecture decision summary

### Vad ändras
- Introducera ny tabell: `accounts`.
- Flytta livscykel från tabell-förflyttning (pending_* -> aktiva tabeller) till statusövergångar i en och samma tabell:
  - `pending` -> `active` -> `disabled`
- Slå ihop ansöknings-/kontoobjekt till en enhetlig modell med:
  - `account_type`: `standard` | `foretagskonto`
  - `status`: `pending` | `active` | `disabled`
  - `name`, `email`, `password_hash`, `personnummer_hash`, `created_at`, `updated_at`
- Behåll `application_requests` som approval-historik, audit och spårbarhet.

### Vad stannar kvar
- `application_requests` kvarstår som historik över inkomna ansökningar, beslut, metadata och adminspårning.
- Existerande användarflöden och användartext i UI (svenska) hålls oförändrade.
- Existerande routes kan initialt finnas kvar men börja peka mot centraliserad service-layer.

### Varför
- Minskar duplicering i schema, route-logik och validering.
- Minskar risk för inkonsistens mellan "pending"- och "active"-tabeller.
- Underlättar framtida roll- och statusutbyggnad utan nya tabeller.
- Möjliggör stegvis och reversibel migrering med dual-read/dual-write.

---

## B) Stegvis rollout-plan

## Phase 0 – Förberedelse och säkerhetsnät
1. Inventera nuvarande modellfält, constraints och användningsmönster i:
   - `functions/database.py`
   - `functions/users.py`
   - `functions/supervisors.py`
   - `functions/applications.py`
   - `app.py`
2. Definiera centrala konstanter (temporärt utan att byta beteende):
   - `ACCOUNT_TYPE_STANDARD`, `ACCOUNT_TYPE_FORETAGSKONTO`
   - `ACCOUNT_STATUS_PENDING`, `ACCOUNT_STATUS_ACTIVE`, `ACCOUNT_STATUS_DISABLED`
3. Lägg till read-only observability-mått:
   - antal pending users/supervisors
   - antal aktiva users/supervisors
   - mismatch-varningar vid jämförelse mellan gammal och ny read-path
4. Lägg feature flaggar (t.ex. env):
   - `ACCOUNTS_V2_WRITE_ENABLED`
   - `ACCOUNTS_V2_READ_ENABLED`
   - `ACCOUNTS_V2_ROUTE_UNIFIED`

## Phase 1 – Schema introduction
1. Skapa `accounts`-tabell via migration utan att röra gamla tabeller.
2. Lägg index/constraints (se sektion C).
3. Lägg SQLAlchemy-modell och repository-funktioner i `functions/database.py`.
4. Ingen route ändras ännu; produktion använder fortsatt legacy-läsning.

## Phase 2 – Backfill
1. Kör idempotent backfill-jobb:
   - `pending_users` -> `accounts(status='pending', account_type='standard')`
   - `users` -> `accounts(status='active', account_type='standard')`
   - `pending_supervisors` -> `accounts(status='pending', account_type='foretagskonto')`
   - `supervisors` -> `accounts(status='active', account_type='foretagskonto')`
2. Logga collisions och policyutfall (ej silent overwrite).
3. Kör verifieringsskript:
   - row counts per typ/status
   - email-/personnummer-unikhet
   - checksum/hash-jämförelse

## Phase 3 – Dual-write compatibility
1. Vid alla skapa/approve/disable-händelser: skriv både legacy-tabeller och `accounts`.
2. Lägg in verifiering efter write (best effort):
   - om mismatch -> logga kritisk händelse + fallback till legacy som source of truth.
3. Fortsatt read från legacy (för låg risk).

## Phase 4 – Dual-read + service-layer refactor
1. Inför central account-service (t.ex. i `functions/accounts.py`) som kapslar:
   - create pending account
   - approve account
   - disable account
   - authenticate active account
2. App-lagret läser från `accounts` när `ACCOUNTS_V2_READ_ENABLED=true`, annars legacy.
3. Behåll API-shape oförändrad genom adapter-mapping från `Account` till befintliga vyobjekt.

## Phase 5 – Route consolidation
1. Slå ihop duplicerade apply-handlers för standard/företag till en gemensam intern tjänst.
2. Behåll externa route-URL:er för bakåtkompatibilitet, men låt båda routes kalla samma underliggande funktion.
3. Centralisera validering:
   - e-postnormalisering
   - personnummerkrav beroende på `account_type`
   - statusregler

## Phase 6 – Decommission old tables
1. När läsning/skrivning är stabil i produktion (definierad observationstid, t.ex. 2–4 veckor):
   - slå av dual-write
   - migrera fullt till `accounts`-läsning
2. Arkivera/backup legacy-tabeller.
3. Ta bort `pending_users`, `users`, `pending_supervisors`, `supervisors` i separat migration.
4. Rensa död kod och feature flaggar.

---

## C) Data migration details

### Exakt mappning från gamla tabeller

| Legacy-tabell | accounts.account_type | accounts.status | Kommentar |
|---|---|---|---|
| `pending_users` | `standard` | `pending` | `password_hash` kan vara NULL om inte satt ännu |
| `users` | `standard` | `active` | aktivt konto |
| `pending_supervisors` | `foretagskonto` | `pending` | ofta företagsflöde |
| `supervisors` | `foretagskonto` | `active` | aktivt företagskonto |

Fältmappning (princip):
- `name` <- motsvarande namnfält.
- `email` <- normaliserad canonical form (se nedan).
- `password_hash` <- befintlig hash, annars `NULL`.
- `personnummer_hash` <- hash från legacy om finns, annars `NULL`.
- `created_at` <- legacy created timestamp om finns, annars migreringstid.
- `updated_at` <- migreringstid eller legacy updated timestamp.

### Canonical email storage (val + motivering)
**Val:** lagra e-post i lowercase och trimmat (`strip + lower`) i `accounts.email`.

**Motivering:**
- Praktiskt case-insensitive inloggning/unikhet.
- Enklare unika index och färre dolda dubbletter.
- Minskar branchande kod där vissa flöden normaliserar och andra inte.

**Genomförande:**
- Normalisera vid write i service-layer.
- Backfill normaliserar historiska värden.
- Spara gärna original i separat auditfält endast om affärsbehov finns (inte nödvändigt för Option B).

### Uniqueness/index-strategi
Rekommenderade constraints/index:
1. `UNIQUE(email)` för aktiva + pending konton (alternativt partial indexes om disabled ska tillåta återanvändning).
2. Partial unique index på `personnummer_hash` där `personnummer_hash IS NOT NULL` och `status != 'disabled'`.
3. Index på `(status, account_type)` för adminlistor/ansökningsflöde.
4. Index på `created_at` för sortering/rapportering.

### Collision handling rules
1. **Email-kollision mellan pending och active:** active vinner; pending markeras conflict och kräver adminbeslut.
2. **Email-kollision mellan user/supervisor:** skapa en account enligt prioriteringsregel (active före pending), logga incident, länka sekundär rad i migrationsrapport.
3. **Personnummer-kollision:** behandla som kritisk dataintegritetsincident; ingen automatisk merge.
4. Alla kollisioner skrivs till separat migreringslogg/tabell för manuell uppföljning.

---

## D) Riskanalys + mitigering

### Dataintegritetsrisker
- Felaktig mappning av status/type vid backfill.
- Dubbletter p.g.a. inkonsekvent e-postnormalisering.
- Förlorad historik om gamla tabeller avvecklas för tidigt.

### Mitigeringar
- Idempotenta migrationer + verifieringsjobb före och efter.
- Dual-write-period med automatisk mismatch-loggning.
- Tydlig "source of truth" per fas (legacy först, sedan accounts).
- Backup-snapshot före varje irreversibel fas.

## Rollback Plan
1. Om fel under Phase 1–3: behåll legacy som read-path, stäng av `ACCOUNTS_V2_*` flags.
2. Om fel under Phase 4: växla tillbaka read till legacy omedelbart, fortsätt ev. dual-write tills orsak isolerats.
3. Droppa inte legacy-tabeller förrän stabil drift verifierats.
4. Behåll backfill-script reversibelt (markera/ta bort V2-rader skapade av migrering via batch-id).

### Observability checks
- Räkne-jämförelse per status/type mellan legacy och accounts.
- Andel lyckade ansökningar per konto-typ före/efter ändring.
- Login-felrate per konto-typ.
- Admin-godkännanden: latens och fel.
- Antal "collision" och "mismatch" events.

---

## E) Teststrategi

### Migrationstester
- Testa schema-migration upp/ner i isolerad testdatabas.
- Testa backfill-idempotens (kör två gånger, samma slutresultat).
- Testa collision-scenarier med deterministiska fixtures.

### Enhetstester
- `normalize_email()` med edge cases.
- statusövergångar: pending->active, active->disabled, ogiltiga hopp.
- validering per account_type (personnummer krävs ej för företagskonto om sådan regel gäller).

### End-to-end-flöden
- Standardkonto: ansök -> pending -> admin godkänner -> aktiv inloggning.
- Företagskonto: ansök -> pending -> admin godkänner -> aktiv inloggning.
- Legacy-route-kompatibilitet: samma HTTP-status, redirects och svenska meddelanden.

---

## F) Konkret implementations-backlog (prioriterad)

### `functions/database.py`
1. Lägg `Account`-modell + indexes + constraints.
   - **AC:** migration kan appliceras utan påverkan på legacy-flöden.
2. Lägg databasfunktioner för create/get/update by email/status/type.
   - **AC:** funktionerna täcker pending/active/disabled.

### `functions/applications.py`
1. Extrahera gemensam ansökningslogik till en intern funktion.
   - **AC:** standard/företag använder samma validerings- och create-path.
2. Skriv dual-write till `accounts` bakom feature flag.
   - **AC:** avstängd flag ger exakt legacy-beteende.

### `functions/users.py`
1. Byt intern lookup till account-service (flagstyrt).
   - **AC:** login och användarsökning fungerar i både legacy och V2-läge.

### `functions/supervisors.py`
1. Spegla user-refaktor till account-service.
   - **AC:** inga regressions i supervisor-autentisering.

### `app.py`
1. Konsolidera apply-handlers till gemensam service-funktion med befintliga routes kvar.
   - **AC:** frontend behöver inga URL-ändringar.
2. Behåll svenska användartexter oförändrade.
   - **AC:** snapshots/response-texttester passerar.

### `tests/`
1. Nya tester för migrations/backfill/dual-read-dual-write.
   - **AC:** täcker mappingregler + collision policy.
2. E2E-tester för båda konto-typer.
   - **AC:** hela ansöknings- och godkännandeflödet verifierat.

---

## G) SQLAlchemy migration pseudo-code (exempel)

```python
# alembic upgrade() - förenklad pseudo-kod
op.create_table(
    "accounts",
    sa.Column("id", sa.Integer(), primary_key=True),
    sa.Column("account_type", sa.String(length=32), nullable=False),
    sa.Column("status", sa.String(length=32), nullable=False),
    sa.Column("name", sa.String(length=255), nullable=False),
    sa.Column("email", sa.String(length=255), nullable=False),
    sa.Column("password_hash", sa.String(length=255), nullable=True),
    sa.Column("personnummer_hash", sa.String(length=255), nullable=True),
    sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    sa.CheckConstraint("account_type IN ('standard', 'foretagskonto')", name="ck_accounts_type"),
    sa.CheckConstraint("status IN ('pending', 'active', 'disabled')", name="ck_accounts_status"),
)

op.create_index("ix_accounts_status_type", "accounts", ["status", "account_type"])
op.create_index("ix_accounts_created_at", "accounts", ["created_at"])
op.create_unique_constraint("uq_accounts_email", "accounts", ["email"])

# Postgres partial unique example
op.execute(
    """
    CREATE UNIQUE INDEX IF NOT EXISTS uq_accounts_personnummer_active
    ON accounts (personnummer_hash)
    WHERE personnummer_hash IS NOT NULL AND status <> 'disabled'
    """
)
```

```python
# backfill pseudo-kod

def normalize_email(raw: str) -> str:
    return raw.strip().lower()


def upsert_account_from_legacy(session, row, account_type, status):
    email = normalize_email(row.email)
    existing = session.query(Account).filter_by(email=email).one_or_none()

    if existing is None:
        session.add(Account(
            account_type=account_type,
            status=status,
            name=row.name,
            email=email,
            password_hash=getattr(row, "password", None),
            personnummer_hash=getattr(row, "personnummer", None),
        ))
        return

    # collision policy (förenklad)
    if existing.status == "active":
        log_collision(row, reason="email_conflict_active_wins")
        return

    if status == "active":
        existing.status = "active"
        existing.account_type = account_type
        existing.name = row.name
        existing.password_hash = getattr(row, "password", None)
        existing.personnummer_hash = getattr(row, "personnummer", None)
        return

    log_collision(row, reason="email_conflict_pending")
```

---

## H) API-/beteendekompatibilitet (för att inte bryta frontend)
- Behåll existerande URL:er för apply/login/admin under migreringen.
- Behåll response-format, redirects och HTTP-statuskoder.
- Behåll exakt svenska UI-meddelanden och feltexter.
- Om interna objekt byts till `Account`, använd adapter i service-layer så templates/API fortsatt får förväntade fält.
- Inför inga frontend-krav på nya fält innan backend är fullt migrerad.

---

## Definition of Done
- `accounts` finns i produktion med verifierade constraints/index.
- Backfill körd och verifierad utan okända kritiska kollisioner.
- Dual-write och dual-read validerade med observability utan signifikanta mismatchar.
- Standard- och företagsflöden går via central service-layer.
- Apply-routes konsoliderade internt, externa kontrakt oförändrade.
- Legacy-tabeller avvecklade först efter stabil period och rollback-fönster.
- Tester för migration, enhet och E2E passerar i CI.

## Open Questions
1. Ska disabled-konton kunna återanvända samma e-post direkt, eller krävs manuell återaktivering?
2. Är `personnummer_hash` obligatoriskt för alla standardkonton i samtliga flöden?
3. Behöver företagskonto en separat identifierare (t.ex. organisationsnummer-hash) i `accounts` nu eller senare?
4. Finns explicit rollmodell (admin/supervisor/user) som bör modelleras i samma steg, eller hållas separat?
5. Hur länge behöver legacy-tabeller vara läsbara för revisions-/rapportbehov?

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
