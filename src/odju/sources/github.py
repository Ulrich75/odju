"""Données publiques GitHub. GITHUB_TOKEN est facultatif et augmente les quotas."""

from __future__ import annotations

import os

import httpx

from odju.models import Finding, Severity
from odju.sources.errors import SourceFailed
from odju.target import Target, normalize_name

API = "https://api.github.com"
_MAX_PROFILES = 5
_PROFILE_FIELDS = {
    "email": "email", "company": "entreprise", "location": "localisation",
    "blog": "site web", "bio": "biographie", "twitter_username": "compte X",
}


def check(target: Target, client: httpx.Client) -> list[Finding]:
    if target.kind == "email":
        return _by_email(target.raw, client)
    return _by_name(target.raw, client)


def _get(client: httpx.Client, path: str, params: dict | None = None) -> dict:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    response = client.get(f"{API}{path}", params=params, headers=headers)
    if response.status_code in (403, 429):
        raise SourceFailed("quota atteint, définissez GITHUB_TOKEN ou réessayez plus tard")
    if response.status_code != 200:
        raise SourceFailed(f"HTTP {response.status_code}")
    return response.json()


def _exposed_fields(profile: dict) -> list[str]:
    return [label for key, label in _PROFILE_FIELDS.items() if profile.get(key)]


def _by_email(email: str, client: httpx.Client) -> list[Finding]:
    findings: list[Finding] = []
    users = _get(client, "/search/users", {"q": f"{email} in:email", "per_page": _MAX_PROFILES})
    for item in users.get("items", []):
        profile = _get(client, f"/users/{item['login']}")
        exact = (profile.get("email") or "").lower() == email
        findings.append(
            Finding(
                kind="public_profile",
                title=f"Profil GitHub lié : {item['login']}",
                source="GitHub",
                source_url=item.get("html_url", ""),
                severity=Severity.MOYEN if exact else Severity.FAIBLE,
                confidence=95 if exact else 60,
                confidence_reason=(
                    "L'email figure à l'identique sur le profil public."
                    if exact
                    else "La recherche GitHub associe ce compte à l'email, sans qu'il soit affiché sur le profil."
                ),
                exposed=_exposed_fields(profile),
                summary="Compte public associé à cet email.",
                tags=["public_email"],
            )
        )

    commits = _get(client, "/search/commits", {"q": f"author-email:{email}", "per_page": 1})
    total = commits.get("total_count", 0)
    if total:
        first = (commits.get("items") or [{}])[0]
        findings.append(
            Finding(
                kind="git_history",
                title=f"Email visible dans {total} commit(s) public(s)",
                source="GitHub",
                source_url=first.get("html_url", "https://github.com"),
                severity=Severity.FAIBLE,
                confidence=90,
                confidence_reason="Auteur de commit identique, mais ce champ est déclaratif dans git.",
                exposed=["adresses email", "nom d'auteur git"],
                summary="L'historique Git public conserve l'adresse des auteurs de commits.",
                tags=["git_email"],
            )
        )
    return findings


def _by_name(name: str, client: httpx.Client) -> list[Finding]:
    users = _get(client, "/search/users", {"q": f'"{name}" in:name', "per_page": _MAX_PROFILES})
    wanted = normalize_name(name)
    findings = []
    for item in users.get("items", []):
        profile = _get(client, f"/users/{item['login']}")
        exact = normalize_name(profile.get("name") or "") == wanted
        findings.append(
            Finding(
                kind="public_profile",
                title=f"Profil GitHub possible : {item['login']}",
                source="GitHub",
                source_url=item.get("html_url", ""),
                severity=Severity.FAIBLE if exact else Severity.INFO,
                confidence=45 if exact else 20,
                confidence_reason=(
                    "Nom identique, mais un nom n'identifie pas une personne : homonyme possible."
                    if exact
                    else "Nom seulement proche : homonyme probable."
                ),
                exposed=_exposed_fields(profile),
                summary="Profil public à confirmer manuellement.",
                tags=["homonym", "public_email"],
            )
        )
    return findings
