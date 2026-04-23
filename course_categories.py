# Copyright (c) Liam Suorsa and Mika Suorsa
# Konstanter och hjälpmetoder för kurskategorier.

from __future__ import annotations

from typing import Iterable, List, Tuple

# Lista över tillgängliga kurskategorier grupperade per rubrik.
COURSE_CATEGORY_GROUPS: List[Tuple[str, List[Tuple[str, str]]]] = [
    (
        "🦺 Arbetsmiljö & säkerhet",
        [
            ("arbetsmiljoutbildning-grund", "Arbetsmiljöutbildning – grund"),
            ("sam", "Systematiskt arbetsmiljöarbete (SAM)"),
            ("bam-battre-arbetsmiljo", "BAM – Bättre Arbetsmiljö"),
            ("sam-for-chefer", "SAM för chefer"),
            ("skyddsombud-grund", "Skyddsombudsutbildning – grund"),
            ("skyddsombud-fortsattning", "Skyddsombudsutbildning – fortsättning"),
            ("heta-arbeten", "Heta Arbeten"),
            ("brandfarliga-arbeten-alternativ", "Brandfarliga arbeten (alternativ)"),
            ("brandskydd-grund", "Brandskyddsutbildning – grund"),
            ("brandskyddsansvarig", "Brandskyddsansvarig"),
            ("sba-systematiskt-brandskyddsarbete", "SBA – Systematiskt brandskyddsarbete"),
            ("utrymningsledare", "Utrymningsledare"),
            ("anlaggningsskotare-brandlarm", "Anläggningsskötare brandlarm"),
            ("anlaggningsskotare-sprinkler", "Anläggningsskötare sprinkler"),
            ("forsta-hjalpen", "Första hjälpen"),
            ("hlr-vuxen", "HLR – vuxen"),
            ("hlr-barn", "HLR – barn"),
            ("hlr-med-hjartstartare", "HLR med hjärtstartare"),
            ("psykisk-ohalsa-arbetsplatsen", "Psykisk ohälsa på arbetsplatsen"),
            ("hot-och-vald-arbetsmiljon", "Hot och våld i arbetsmiljön"),
            ("krishantering", "Krishantering"),
            ("ergonomi-arbetsplatsen", "Ergonomi på arbetsplatsen"),
            ("belastningsergonomi", "Belastningsergonomi"),
            ("ensamarbete-risker-ansvar", "Ensamarbete – risker och ansvar"),
            ("arbete-i-slutna-utrymmen", "Arbete i slutna utrymmen"),
            ("maskinsakerhet", "Maskinsäkerhet"),
            ("ovrigt-arbetsmiljo-sakerhet", "Övrigt - Arbetsmiljö & säkerhet"),
        ],
    ),
    (
        "🏗️ Bygg, anläggning & industri",
        [
            ("fallskydd-grund", "Fallskydd – grund"),
            ("fallskydd-repetition", "Fallskydd – repetition"),
            ("stallningsbyggnad-2-9-m", "Ställningsbyggnad 2–9 m"),
            ("stallningsbyggnad-over-9-m", "Ställningsbyggnad över 9 m"),
            ("säkra-lyft", "Säkra lyft"),
            ("liftutbildning", "Liftutbildning"),
            ("traversutbildning", "Traversutbildning"),
            ("maskinforarutbildning", "Maskinförarutbildning"),
            ("asbestutbildning", "Asbestutbildning"),
            ("kvartsdamm-hantering-risker", "Kvartsdamm – hantering och risker"),
            ("kemikaliehantering", "Kemikaliehantering"),
            ("sakerhet-schakt-markarbete", "Säkerhet vid schakt och markarbete"),
            ("elsakerhet-allman", "Elsäkerhet – allmän"),
            ("esa-grund", "ESA – grund"),
            ("esa-arbete", "ESA – arbete"),
            ("esa-repetition", "ESA – repetition"),
            ("hogspanning-sakerhetsutbildning", "Högspänning – säkerhetsutbildning"),
            ("loto-las-tilltradesrutiner", "Lås- och tillträdesrutiner (LOTO)"),
            (
                "bygg-arbetsmiljo-samordning-bas-u-bas-p",
                "Bygg Arbetsmiljö Samordning - BAS-U, BAS-P",
            ),
            ("ovrigt-bygg-anlaggning-industri", "Övrigt - Bygg, anläggning & industri"),
        ],
    ),
    (
        "🚆 Järnväg",
        [
            ("allman-jarnvagsteknik", "Allmän järnvägsteknik"),
            (
                "enskilt-vistas-i-spar-basavista-grund",
                "Att enskilt vistas i spår – grund (BÄSÄVISTA)",
            ),
            ("besiktningsman-tsa", "Besiktningsman TSA"),
            (
                "elsakerhetsledare-jarnvag-grund",
                "Elsäkerhetsledare på järnväg - grund",
            ),
            (
                "elsakerhetsledare-jarnvag-repetition",
                "Elsäkerhetsledare på järnväg – repetition",
            ),
            (
                "operator-tsa-ta-grund",
                "Operatör TSA och/eller TA – grund",
            ),
            (
                "repetition-sos-ledare-sos-planerare-tillsyningsman-e2-operator-tsa-ta-tsm",
                "Repetition - SoS-ledare, SoS-planerare, Tillsyningsman, E2, "
                "Operatör TSA och Operatör TA, TSM spärrfärd och växling",
            ),
            (
                "sos-ledare-basaskydd",
                "Skydds- och säkerhetsledare (SoS-ledare) (BASÄSKYDD)",
            ),
            (
                "sos-planerare-sos-pl",
                "Skydds- och säkerhetsplanerare (SoS-planerare) (SoS-pl)",
            ),
            (
                "arbeten-sparstabilitet-grund-bastab",
                "Arbeten som påverkar spårstabiliteten – grund (BASTAB)",
            ),
            (
                "arbeten-sparstabilitet-repetition-bastab",
                "Arbeten som påverkar spårstabiliteten – repetition (BASTAB)",
            ),
            (
                "tillsyningsman-hms-vagvakt-basatsm",
                "Tillsyningsman skydd i system H/M/S samt vägvakt (BASÄTSM)",
            ),
            (
                "tillsyningsman-e2",
                "Tillsyningsman skydd i system E2",
            ),
            (
                "tillsyningsman-e3",
                "Tillsyningsman skydd i system E3",
            ),
            (
                "tillsyningsman-sparrfard-vaxling",
                "Tillsyningsman spärrfärd och växling",
            ),
            ("skyddsanvisningar", "Skyddsanvisningar"),
            ("signalteknik-grund", "Signalteknik - grund"),
            ("ykb-fortbildning", "YKB – fortbildning"),
            ("ykb-grund", "YKB – grund"),
            (
                "ovrigt-transport-jarnvag-logistik",
                "Övrigt - Transport, järnväg & logistik",
            ),
        ],
    ),
    (
        "🚚 Transport & logistik",
        [
            ("adr-1-3-farligt-gods-grund", "ADR 1.3 – Farligt gods (grund)"),
            ("adr-1-3-farligt-gods-repetition", "ADR 1.3 – Farligt gods (repetition)"),
            ("adr-forare-styckegods", "ADR – förare styckegods"),
            ("adr-forare-tank", "ADR – förare tank"),
            ("adr-sakerhetsradgivare-grund", "ADR – säkerhetsrådgivare (grund)"),
            (
                "adr-sakerhetsradgivare-repetition",
                "ADR – säkerhetsrådgivare (repetition)",
            ),
            ("apv-steg-1-grundkompetens", "APV Steg 1 – Grundkompetens"),
            ("apv-steg-2-utforande-ansvar", "APV Steg 2 – Utförande och ansvar"),
            ("apv-steg-3-projektering-planering", "APV Steg 3 – Projektering och planering"),
            ("eco-driving-personbil", "Eco Driving – personbil"),
            ("eco-driving-lastbil", "Eco Driving – lastbil"),
            ("fordonskannedom-tunga-fordon", "Fordonskännedom – tunga fordon"),
            ("fordonssakerhet-lastsakring", "Fordonssäkerhet och lastsäkring"),
            ("godshantering-terminalarbete", "Godshantering och terminalarbete"),
            ("lastsakring-grund", "Lastsäkring – grund"),
            ("lastsakring-fordjupning", "Lastsäkring – fördjupning"),
            ("logistik-flodesoptimering-grund", "Logistik och flödesoptimering – grund"),
            (
                "logistik-flodesoptimering-fordjupning",
                "Logistik och flödesoptimering – fördjupning",
            ),
            ("planering-transporter", "Planering av transporter"),
            (
                "sakerhet-lastning-lossning",
                "Säkerhet vid lastning och lossning",
            ),
            ("transportjuridik-grund", "Transportjuridik – grund"),
            ("transportekonomi", "Transportekonomi"),
            ("transportledning-grund", "Transportledning – grund"),
            ("transportledning-fordjupning", "Transportledning – fördjupning"),
            ("truckutbildning-a", "Truckutbildning A"),
            ("truckutbildning-b", "Truckutbildning B"),
            ("truckutbildning-c", "Truckutbildning C"),
            ("tunga-lyft-logistik", "Tunga lyft inom logistik"),
            ("yrkesforarens-ansvar-regelverk", "Yrkesförarens ansvar och regelverk"),
            ("yrkesforarens-arbetsmiljo", "Yrkesförarens arbetsmiljö"),
            (
                "yttre-miljokrav-transporter",
                "Yttre miljökrav vid transporter (miljözoner, utsläpp m.m.)",
            ),
            ("ovrigt-transport-logistik", "Övrigt - Transport & logistik"),
        ],
    ),
    (
        "💻 IT, teknik & administration",
        [
            ("agil-projektledning", "Agil projektledning"),
            ("ai-utbildning", "AI utbildning"),
            ("arbetsmiljoledning-iso-45001", "Arbetsmiljöledning ISO 45001"),
            ("avvikelsehantering", "Avvikelsehantering"),
            ("dokumentation-sparbarhet", "Dokumentation & spårbarhet"),
            ("gdpr-fordjupning", "GDPR – fördjupning"),
            ("gdpr-grund", "GDPR – grund"),
            ("informationssakerhet", "Informationssäkerhet"),
            ("internrevisor-iso", "Internrevisor ISO"),
            ("it-sakerhet-grund", "IT-säkerhet – grund"),
            ("kvalitetsledning-iso-9001", "Kvalitetsledning ISO 9001"),
            ("lean-grund", "Lean – grund"),
            ("miljoledning-iso-14001", "Miljöledning ISO 14001"),
            ("projektledning-fordjupning", "Projektledning – fördjupning"),
            ("projektledning-grund", "Projektledning – grund"),
            ("riskanalys-riskbedomning", "Riskanalys och riskbedömning"),
            ("ovrigt-it-teknik-administration", "Övrigt – IT, teknik & administration"),
        ],
    ),
    (
        "👥 Ledarskap, HR & mjuka färdigheter",
        [
            ("alkohol-droger-arbetslivet", "Alkohol och droger i arbetslivet"),
            ("arbetsledarutbildning", "Arbetsledarutbildning"),
            ("arbetsratt-grund", "Arbetsrätt – grund"),
            ("chefens-arbetsmiljoansvar", "Chefens arbetsmiljöansvar"),
            ("feedback-svara-samtal", "Feedback och svåra samtal"),
            ("introduktion-nyanstallda-bas", "Introduktion för nyanställda (BAS)"),
            ("jamstalldhet-diskriminering", "Jämställdhet och diskriminering"),
            ("kommunikation-arbetsplatsen", "Kommunikation på arbetsplatsen"),
            ("konflikthantering", "Konflikthantering"),
            ("kundservice", "Kundservice"),
            ("ledarskap-alla-grund", "Ledarskap (alla) – grund"),
            ("likabehandling", "Likabehandling"),
            ("medarbetarsamtal", "Medarbetarsamtal"),
            ("pedagogik-retorik", "Pedagogik och retorik"),
            ("rehabiliteringsansvar", "Rehabiliteringsansvar"),
            ("stresshantering", "Stresshantering"),
            ("tidshantering", "Tidshantering"),
            ("ovrigt-ledarskap-hr-mjuka-fardigheter", "Övrigt – Ledarskap, HR & mjuka färdigheter"),
        ],
    ),
    (
        "🏥 Vård, omsorg & samhälle",
        [
            ("basala-hygienrutiner", "Basala hygienrutiner"),
            ("brandskydd-lokaler-hem", "Brandskydd – Lokaler och hem"),
            ("brandskydd-vard-omsorg", "Brandskydd inom vård och omsorg"),
            ("demensutbildning", "Demensutbildning"),
            ("etik-vard-omsorg", "Etik i vård och omsorg"),
            ("forflyttningsteknik", "Förflyttningsteknik"),
            ("lakemedelshantering-grund", "Läkemedelshantering – grund"),
            ("sekretess-tystnadsplikt", "Sekretess och tystnadsplikt"),
            ("saker-patienthantering", "Säker patienthantering"),
            ("smittskydd", "Smittskydd"),
            ("valdsprevention-varden", "Våldsprevention i vården"),
            ("ovrigt-vard-omsorg-samhalle", "Övrigt – Vård, omsorg & samhälle"),
        ],
    ),
]


def _flatten_category_groups(
    groups: Iterable[Tuple[str, List[Tuple[str, str]]]],
) -> List[Tuple[str, str]]:
    return [item for _, items in groups for item in items]


# Lista över tillgängliga kurskategorier (slug, etikett)
COURSE_CATEGORIES: List[Tuple[str, str]] = _flatten_category_groups(
    COURSE_CATEGORY_GROUPS
)

_CATEGORY_LOOKUP = {slug: label for slug, label in COURSE_CATEGORIES}


def normalize_category_slugs(values: Iterable[str]) -> List[str]:
    # Filtrera och normalisera inkommande kategori-slugs.

    normalized: List[str] = []
    seen: set[str] = set()
    for raw in values:
        slug = raw.strip().lower()
        if slug and slug in _CATEGORY_LOOKUP and slug not in seen:
            normalized.append(slug)
            seen.add(slug)
    return normalized


def labels_for_slugs(slugs: Iterable[str]) -> List[str]:
    # Returnera svenska etiketter för angivna kategori-slugs.

    return [_CATEGORY_LOOKUP[slug] for slug in slugs if slug in _CATEGORY_LOOKUP]
