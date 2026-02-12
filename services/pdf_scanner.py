# Copyright (c) Liam Suorsa
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
from typing import Iterable, Literal, NamedTuple

ScanDecision = Literal["ALLOW", "REJECT"]

DANGEROUS_MARKERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bjavascript\b", re.IGNORECASE), "JavaScript"),
    (re.compile(r"\blaunch\b", re.IGNORECASE), "Launch"),
    (re.compile(r"\bembeddedfiles?\b", re.IGNORECASE), "EmbeddedFile"),
    (re.compile(r"\bfileattachment\b", re.IGNORECASE), "EmbeddedFile"),
    (re.compile(r"\bxfa\b", re.IGNORECASE), "XFA"),
    (re.compile(r"\brichmedia\b", re.IGNORECASE), "RichMedia"),
    (re.compile(r"\bgotoe\b", re.IGNORECASE), "GoToE"),
    (re.compile(r"\bgotor\b", re.IGNORECASE), "GoToR"),
    (re.compile(r"\buri\b", re.IGNORECASE), "URI"),
    (re.compile(r"\bsubmitform\b", re.IGNORECASE), "SubmitForm"),
)

BENIGN_OPENACTION_MARKERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bopenaction\b", re.IGNORECASE), "OpenAction"),
    (re.compile(r"\bgoto\b", re.IGNORECASE), "GoTo"),
    (re.compile(r"/(?:fit|xyz)\b", re.IGNORECASE), "ViewDestination"),
)

DANGEROUS_FINDING_LABELS = {label for _pattern, label in DANGEROUS_MARKERS}
BENIGN_OPENACTION_FINDING_LABELS = {label for _pattern, label in BENIGN_OPENACTION_MARKERS}


class ScanVerdict(NamedTuple):
    decision: ScanDecision
    findings: list[str]


def _collect_matches_from_strings(strings: Iterable[str]) -> set[str]:
    matches: set[str] = set()
    for candidate in strings:
        for pattern, label in DANGEROUS_MARKERS:
            if pattern.search(candidate):
                matches.add(label)
        for pattern, label in BENIGN_OPENACTION_MARKERS:
            if pattern.search(candidate):
                matches.add(label)
    return matches


def _walk_structure(obj) -> set[str]:
    matches: set[str] = set()
    if isinstance(obj, dict):
        matches |= _collect_matches_from_strings(obj.keys())
        for value in obj.values():
            matches |= _walk_structure(value)
    elif isinstance(obj, list):
        for item in obj:
            matches |= _walk_structure(item)
    elif isinstance(obj, str):
        matches |= _collect_matches_from_strings([obj])
    return matches


def is_dangerous_finding(finding: str) -> bool:
    return finding in DANGEROUS_FINDING_LABELS


def is_benign_openaction_only(findings: set[str]) -> bool:
    if not findings:
        return False
    if "OpenAction" not in findings:
        return False
    if any(is_dangerous_finding(finding) for finding in findings):
        return False
    return findings.issubset(BENIGN_OPENACTION_FINDING_LABELS)


def scan_pdf_bytes(pdf_bytes: bytes, logger: logging.Logger | None = None) -> ScanVerdict:
    """Analysera PDF med Quicksand och returnera ALLOW eller REJECT."""

    logger = logger or logging.getLogger(__name__)
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(pdf_bytes)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["quicksand", "-f", "json", tmp_path],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            text=True,
        )
    except FileNotFoundError:
        logger.exception("Quicksand saknas på systemet")
        raise ValueError("Säkerhetsskannern är inte tillgänglig just nu.")
    except subprocess.TimeoutExpired:
        logger.warning("Quicksand-tidgräns överskreds för %s", tmp_path)
        raise ValueError("PDF:en kunde inte skannas i tid.")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            logger.warning("Kunde inte ta bort temporär PDF %s", tmp_path)

    findings: set[str] = set()
    stdout = result.stdout or ""
    stderr = result.stderr or ""

    try:
        parsed_output = json.loads(stdout) if stdout else None
    except json.JSONDecodeError:
        parsed_output = None

    if parsed_output is not None:
        findings |= _walk_structure(parsed_output)

    if not findings:
        findings |= _collect_matches_from_strings([stdout, stderr])

    decision: ScanDecision = "REJECT" if findings else "ALLOW"
    benign_openaction_only = is_benign_openaction_only(findings)

    if decision == "REJECT" and benign_openaction_only:
        logger.info("PDF nedgraderad från REJECT till ALLOW: endast benign OpenAction/view-action")
        decision = "ALLOW"

    logger.info(
        "Quicksand-resultat: %s (fynd: %s)",
        decision,
        ", ".join(sorted(findings)) if findings else "inga",
    )

    if decision == "REJECT":
        logger.warning("PDF blockerad efter skanning")

    if result.returncode not in {0} and decision == "ALLOW":
        if benign_openaction_only:
            logger.warning(
                "Quicksand returnerade kod %s men output klassades som benign OpenAction",
                result.returncode,
            )
        else:
            # Säkerhetsavvägning: fail closed vid okänd/nonzero scanner-status för att
            # minska risken för false negatives, även om det kan ge fler false positives.
            logger.error(
                "Quicksand returnerade kod %s utan tydligt benign klassificering: %s",
                result.returncode,
                stderr,
            )
            raise ValueError("Säkerhetsskannern rapporterade ett fel.")

    return ScanVerdict(decision, sorted(findings))
