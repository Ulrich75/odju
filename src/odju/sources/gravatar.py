"""Profil public Gravatar lié au hash de l'email."""

from __future__ import annotations

import hashlib

import httpx

from odju.models import Finding, Severity
from odju.sources.errors import SourceFailed
from odju.target import Target

URL = "https://api.gravatar.com/v3/profiles/{digest}"
_FIELDS = {
    "display_name": "nom affiché", "location": "localisation", "job_title": "poste",
    "company": "entreprise", "description": "biographie", "verified_accounts": "comptes liés",
}


def check(target: Target, client: httpx.Client) -> list[Finding]:
    digest = hashlib.sha256(target.raw.encode()).hexdigest()
    response = client.get(URL.format(digest=digest))
    if response.status_code == 404:
        return []
    if response.status_code != 200:
        raise SourceFailed(f"HTTP {response.status_code}")

    profile = response.json()
    return [
        Finding(
            kind="public_profile",
            title="Profil Gravatar public",
            source="Gravatar",
            source_url=str(profile.get("profile_url") or "https://gravatar.com"),
            severity=Severity.FAIBLE,
            confidence=99,
            confidence_reason="Le profil correspond exactement au hash de l'email.",
            exposed=[label for key, label in _FIELDS.items() if profile.get(key)],
            summary="Un profil public est relié à cet email et peut servir à faire des recoupements.",
            tags=["public_email"],
        )
    ]
