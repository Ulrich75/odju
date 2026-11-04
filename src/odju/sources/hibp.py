"""Have I Been Pwned : https://haveibeenpwned.com/API/v3 (clé HIBP_API_KEY requise)."""

from __future__ import annotations

import os
import re
from urllib.parse import quote

import httpx

from odju.models import Finding
from odju.scoring import breach_severity, breach_tags, translate
from odju.sources.errors import SourceFailed, SourceSkipped
from odju.target import Target

URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
_TAGS = re.compile(r"<[^>]+>")


def check(target: Target, client: httpx.Client) -> list[Finding]:
    api_key = os.environ.get("HIBP_API_KEY")
    if not api_key:
        raise SourceSkipped("clé HIBP_API_KEY absente")

    response = client.get(
        URL.format(account=quote(target.raw, safe="")),
        params={"truncateResponse": "false"},
        headers={"hibp-api-key": api_key},
    )
    if response.status_code == 404:
        return []
    if response.status_code != 200:
        raise SourceFailed(f"HTTP {response.status_code}")
    return [_to_finding(item) for item in response.json()]


def _to_finding(item: dict) -> Finding:
    classes = item.get("DataClasses") or []
    verified = bool(item.get("IsVerified"))
    domain = item.get("Domain") or ""
    name = item.get("Title") or item.get("Name") or "inconnue"
    return Finding(
        kind="breach",
        title=f"Fuite de données : {name}",
        source="Have I Been Pwned",
        source_url=f"https://{domain}" if domain else "https://haveibeenpwned.com",
        severity=breach_severity(classes),
        confidence=98 if verified else 70,
        confidence_reason=(
            "Email trouvé à l'identique dans une fuite vérifiée par HIBP."
            if verified
            else "Email trouvé à l'identique, mais la fuite n'est pas vérifiée."
        ),
        exposed=[translate(c) for c in classes],
        date=item.get("BreachDate") or "",
        summary=_TAGS.sub("", item.get("Description") or ""),
        tags=breach_tags(classes),
    )
