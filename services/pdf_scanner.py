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

DANGEROUS_MARKERS: dict[re.Pattern[str], str] = {
    re.compile(r"\bjavascript\b", re.IGNORECASE): "JavaScript",
    re.compile(r"\blaunch\b", re.IGNORECASE): "Launch",
    re.compile(r"\bembeddedfiles?\b", re.IGNORECASE): "EmbeddedFile",
    re.compile(r"\bfileattachment\b", re.IGNORECASE): "EmbeddedFile",
    re.compile(r"\bxfa\b", re.IGNORECASE): "XFA",
    re.compile(r"\brichmedia\b", re.IGNORECASE): "RichMedia",
    re.compile(r"\bgotoe\b", re.IGNORECASE): "GoToE",
    re.compile(r"\bgotor\b", re.IGNORECASE): "GoToR",
    re.compile(r"\buri\b", re.IGNORECASE): "URI",
    re.compile(r"\bsubmitform\b", re.IGNORECASE): "SubmitForm",
}

BENIGN_OPENACTION_MARKERS: dict[re.Pattern[str], str] = {
    re.compile(r"\bopenaction\b", re.IGNORECASE): "OpenAction",
    re.compile(r"/(fit|xyz)\b", re.IGNORECASE): "ViewDestination",
    re.compile(r"\bgoto\b", re.IGNORECASE): "GoTo",
}

DANGEROUS_FINDING_LABELS = set(DANGEROUS_MARKERS.values())
BENIGN_OPENACTION_LABELS = {"OpenAction", "ViewDestination", "GoTo"}


class ScanVerdict(NamedTuple):
    decision: ScanDecision
    findings: list[str]


def _collect_matches_from_strings(strings: Iterable[str]) -> set[str]:
    matches: set[str] = set()
    for candidate in strings:
        for pattern, label in DANGEROUS_MARKERS.items():
            if pattern.search(candidate):
                matches.add(label)
        for pattern, label in BENIGN_OPENACTION_MARKERS.items():
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
    if any(is_dangerous_finding(finding) for finding in findings):
        return False
    return any(finding in BENIGN_OPENACTION_LABELS for finding in findings)


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

    json_parsed = parsed_output is not None

    if json_parsed:
        findings |= _walk_structure(parsed_output)

    if not findings:
        findings |= _collect_matches_from_strings([stdout, stderr])

    preliminary_decision: ScanDecision = "REJECT" if findings else "ALLOW"
    decision: ScanDecision = preliminary_decision

    if preliminary_decision == "REJECT" and is_benign_openaction_only(findings):
        decision = "ALLOW"
        logger.info(
            "PDF nedgraderad från REJECT till ALLOW: endast benign OpenAction/view-action hittades"
        )

    if result.returncode not in {0}:
        if json_parsed and is_benign_openaction_only(findings):
            decision = "ALLOW"
            logger.warning(
                "Quicksand returnerade kod %s men JSON visar endast benign OpenAction/view-action",
                result.returncode,
            )
        elif any(is_dangerous_finding(finding) for finding in findings):
            decision = "REJECT"
        else:
            # Säkerhetsavvägning: fail closed vid oklar/nonzero körning minskar false negatives
            # (släppta farliga filer) på bekostnad av fler false positives.
            logger.error(
                "Quicksand returnerade kod %s med oklassificerbart resultat: %s",
                result.returncode,
                stderr,
            )
            raise ValueError("Säkerhetsskannern rapporterade ett fel.")

    logger.info(
        "Quicksand-resultat: %s (fynd: %s)",
        decision,
        ", ".join(sorted(findings)) if findings else "inga",
    )

    if decision == "REJECT":
        logger.warning("PDF blockerad efter skanning")

    return ScanVerdict(decision, sorted(findings))
