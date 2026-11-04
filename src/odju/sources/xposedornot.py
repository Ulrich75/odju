"""Fuites de données connues, sans clé d'API : https://xposedornot.com"""

from __future__ import annotations

import httpx

from odju.models import Finding
from odju.scoring import breach_severity, breach_tags, translate
from odju.sources.errors import SourceFailed
from odju.target import Target

URL = "https://api.xposedornot.com/v1/breach-analytics"


def check(target: Target, client: httpx.Client) -> list[Finding]:
    response = client.get(URL, params={"email": target.raw})
    if response.status_code == 404:
        return []
    if response.status_code != 200:
        raise SourceFailed(f"HTTP {response.status_code}")

    exposed = response.json().get("ExposedBreaches") or {}
    return [_to_finding(item) for item in exposed.get("breaches_details") or []]


def _to_finding(item: dict) -> Finding:
    classes = [c for c in (item.get("xposed_data") or "").split(";") if c]
    risk = item.get("password_risk") or "unknown"
    verified = item.get("verified") == "Yes"
    domain = item.get("domain") or ""
    return Finding(
        kind="breach",
        title=f"Fuite de données : {item.get('breach', 'inconnue')}",
        source="XposedOrNot",
        source_url=f"https://{domain}" if domain else "https://xposedornot.com",
        severity=breach_severity(classes, risk),
        confidence=95 if verified else 70,
        confidence_reason=(
            "Email trouvé à l'identique dans une fuite vérifiée."
            if verified
            else "Email trouvé à l'identique, mais la fuite n'est pas vérifiée."
        ),
        exposed=[translate(c) for c in classes],
        date=str(item.get("xposed_date") or ""),
        summary=item.get("details") or "",
        tags=breach_tags(classes),
    )
