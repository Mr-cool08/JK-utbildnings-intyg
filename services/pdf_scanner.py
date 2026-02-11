# Copyright (c) Liam Suorsa
from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from typing import Iterable, Literal, NamedTuple

ScanDecision = Literal["ALLOW", "REJECT"]

SUSPICIOUS_FEATURES = {
    "javascript": "JavaScript",
    "openaction": "OpenAction",
    "embeddedfile": "EmbeddedFile",
    "embeddedfiles": "EmbeddedFile",
    "fileattachment": "EmbeddedFile",
    "xfa": "XFA",
    "acroform": "AcroForm",
    "richmedia": "RichMedia",
    "launch": "Launch",
}


class ScanVerdict(NamedTuple):
    decision: ScanDecision
    findings: list[str]


def _collect_matches_from_strings(strings: Iterable[str]) -> set[str]:
    matches: set[str] = set()
    for candidate in strings:
        candidate_lower = candidate.lower()
        for keyword, label in SUSPICIOUS_FEATURES.items():
            if keyword in candidate_lower:
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

    logger.info(
        "Quicksand-resultat: %s (fynd: %s)",
        decision,
        ", ".join(sorted(findings)) if findings else "inga",
    )

    if decision == "REJECT":
        logger.warning("PDF blockerad efter skanning")

    if result.returncode not in {0} and decision == "ALLOW":
        logger.error("Quicksand returnerade kod %s utan fynd: %s", result.returncode, stderr)
        raise ValueError("Säkerhetsskannern rapporterade ett fel.")

    return ScanVerdict(decision, sorted(findings))
