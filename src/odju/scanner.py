"""Orchestration d'une analyse."""

from __future__ import annotations

import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import httpx

from odju import __version__
from odju.ai import AI, AIError, Mention
from odju.models import Finding, Report, Severity, SourceStatus
from odju.scoring import exposure_score
from odju.sources import SOURCES
from odju.sources.errors import SourceFailed, SourceSkipped
from odju.target import Target

# Une page web ne prouve jamais l'identité autant qu'une correspondance exacte d'email.
_CONFIDENCE_CAP = {"email": 85, "name": 70}
_CATEGORY_SEVERITY = {
    "courtier_donnees": Severity.ELEVE, "annuaire": Severity.MOYEN, "document": Severity.MOYEN,
    "reseau_social": Severity.FAIBLE, "forum": Severity.FAIBLE,
    "professionnel": Severity.INFO, "autre": Severity.FAIBLE,
}


def _run_source(name: str, check, target: Target, client: httpx.Client) -> tuple[SourceStatus, list[Finding]]:
    try:
        findings = check(target, client)
    except SourceSkipped as exc:
        return SourceStatus(name=name, state="skipped", message=str(exc)), []
    except SourceFailed as exc:
        return SourceStatus(name=name, state="error", message=str(exc)), []
    except httpx.HTTPError as exc:
        return SourceStatus(name=name, state="error", message=f"réseau : {type(exc).__name__}"), []
    except (ValueError, KeyError, TypeError, dns.exception.DNSException) as exc:
        return SourceStatus(name=name, state="error", message=f"réponse inattendue : {type(exc).__name__}"), []
    return SourceStatus(name=name, state="ok", count=len(findings)), findings


def mention_to_finding(mention: Mention, target: Target) -> Finding:
    confidence = max(0, min(mention.confidence, _CONFIDENCE_CAP[target.kind]))
    tags = ["web_listing"] + (["homonym"] if target.kind == "name" else [])
    return Finding(
        kind="web_mention",
        title=f"Mention web : {mention.title}",
        source="Recherche web (IA)",
        source_url=mention.url,
        severity=_CATEGORY_SEVERITY[mention.category],
        confidence=confidence,
        confidence_reason=(
            "Estimation de l'IA, plafonnée à "
            f"{_CONFIDENCE_CAP[target.kind]} % car une page web ne prouve pas l'identité."
        ),
        exposed=mention.exposed,
        summary=mention.summary,
        tags=tags,
    )


def _web_search(target: Target, ai: AI | None) -> tuple[SourceStatus, list[Finding]]:
    name = "Recherche web (IA)"
    if ai is None:
        return SourceStatus(name=name, state="skipped", message="IA désactivée ou non configurée"), []
    try:
        findings = [mention_to_finding(m, target) for m in ai.search_mentions(target.raw)]
    except AIError as exc:
        return SourceStatus(name=name, state="error", message=str(exc)), []
    return SourceStatus(name=name, state="ok", count=len(findings)), findings


def _breach_key(finding: Finding) -> str:
    return re.sub(r"[^a-z0-9]", "", finding.title.split(":", 1)[-1].lower())


def merge_duplicates(findings: list[Finding]) -> list[Finding]:
    """Une même fuite peut remonter de plusieurs sources : on la fusionne."""
    merged: dict[str, Finding] = {}
    others: list[Finding] = []
    for finding in findings:
        if finding.kind != "breach":
            others.append(finding)
            continue
        known = merged.get(_breach_key(finding))
        if known is None:
            merged[_breach_key(finding)] = finding
            continue
        known.source = f"{known.source} + {finding.source}"
        known.severity = max(known.severity, finding.severity)
        known.confidence = max(known.confidence, finding.confidence)
        known.exposed = list(dict.fromkeys(known.exposed + finding.exposed))
        known.tags = list(dict.fromkeys(known.tags + finding.tags))
    return list(merged.values()) + others


def scan(
    target: Target,
    consent: str,
    ai: AI | None,
    progress: Callable[[str], None] = lambda _: None,
) -> Report:
    headers = {"User-Agent": f"odju/{__version__} (audit d'exposition)"}
    with httpx.Client(timeout=20.0, headers=headers) as client:
        applicable = [(n, c) for n, kinds, c in SOURCES if target.kind in kinds]
        with ThreadPoolExecutor(max_workers=len(applicable) + 1) as pool:
            futures = [pool.submit(_run_source, n, c, target, client) for n, c in applicable]
            futures.append(pool.submit(_web_search, target, ai))
            results = [future.result() for future in futures]

    statuses = [status for status, _ in results]
    findings = merge_duplicates([f for _, batch in results for f in batch])
    findings.sort(key=lambda f: (-f.severity, -f.confidence, f.title))
    for index, finding in enumerate(findings, start=1):
        finding.id = f"F{index}"

    report = Report(
        target_masked=target.masked,
        target_kind=target.kind,
        consent=consent,
        findings=findings,
        sources=statuses,
        exposure_score=exposure_score(findings),
    )

    if ai is not None and findings:
        progress("Synthèse IA en cours…")
        try:
            report.assessment = ai.assess(report)
        except AIError as exc:
            report.sources.append(SourceStatus(name="Synthèse IA", state="error", message=str(exc)))
    return report
