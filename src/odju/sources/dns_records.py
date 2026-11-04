"""Protection du domaine email contre l'usurpation (SPF, DMARC)."""

from __future__ import annotations

import dns.exception
import dns.resolver
import httpx

from odju.models import Finding, Severity
from odju.sources.errors import SourceFailed, SourceSkipped
from odju.target import Target

# Sur ces domaines, la configuration ne dépend pas de la personne auditée.
PUBLIC_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "outlook.fr", "hotmail.com", "hotmail.fr",
    "live.com", "live.fr", "msn.com", "yahoo.com", "yahoo.fr", "icloud.com", "me.com",
    "proton.me", "protonmail.com", "gmx.com", "gmx.fr", "orange.fr", "free.fr", "sfr.fr",
    "wanadoo.fr", "laposte.net", "aol.com", "yandex.com", "mail.com",
}


def _txt(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=8)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException as exc:
        raise SourceFailed(f"résolution DNS impossible ({type(exc).__name__})") from exc
    return [b"".join(record.strings).decode("utf-8", "replace") for record in answers]


def check(target: Target, client: httpx.Client) -> list[Finding]:
    domain = target.domain
    if domain in PUBLIC_PROVIDERS:
        raise SourceSkipped(f"{domain} est un fournisseur public, hors de votre contrôle")

    findings = []
    spf = [r for r in _txt(domain) if r.lower().startswith("v=spf1")]
    if not spf:
        findings.append(_finding(domain, "Aucun enregistrement SPF", Severity.MOYEN, "spf",
                                 f"{domain} ne déclare pas ses serveurs d'envoi autorisés."))

    dmarc = [r for r in _txt(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        findings.append(_finding(domain, "Aucune politique DMARC", Severity.MOYEN, "dmarc",
                                 f"{domain} n'indique pas quoi faire des emails usurpés."))
    elif "p=none" in dmarc[0].lower().replace(" ", ""):
        findings.append(_finding(domain, "Politique DMARC non appliquée (p=none)", Severity.FAIBLE, "dmarc",
                                 "DMARC est en observation : les emails usurpés ne sont pas bloqués."))
    return findings


def _finding(domain: str, title: str, severity: Severity, tag: str, summary: str) -> Finding:
    return Finding(
        kind="domain",
        title=f"{title} sur {domain}",
        source="DNS",
        source_url=f"https://{domain}",
        severity=severity,
        confidence=100,
        confidence_reason="Constat direct sur les enregistrements DNS publics du domaine.",
        exposed=["usurpation d'email possible"],
        summary=summary,
        tags=[tag],
    )
