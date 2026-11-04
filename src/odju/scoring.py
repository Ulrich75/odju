"""Règles déterministes de criticité et de score.

La criticité ne dépend jamais de l'IA : deux analyses des mêmes données donnent le même résultat.
"""

from __future__ import annotations

from odju.models import Finding, Severity

_CRITICAL = (
    "credit card", "bank account", "payment", "social security", "government issued",
    "passport", "auth token", "security questions",
)
_IDENTITY = (
    "physical address", "phone number", "date of birth", "dates of birth",
    "geographic location", "ip address",
)

_LABELS = {
    "email addresses": "adresses email", "passwords": "mots de passe",
    "password hints": "indices de mot de passe", "names": "noms",
    "usernames": "identifiants", "phone numbers": "numéros de téléphone",
    "physical addresses": "adresses postales", "dates of birth": "dates de naissance",
    "ip addresses": "adresses IP", "genders": "genre",
    "geographic locations": "localisation", "credit cards": "cartes bancaires",
    "bank account numbers": "comptes bancaires", "auth tokens": "jetons d'authentification",
    "private messages": "messages privés", "security questions and answers": "questions secrètes",
    "social security numbers": "numéros de sécurité sociale",
    "government issued ids": "pièces d'identité",
}


def translate(data_class: str) -> str:
    return _LABELS.get(data_class.strip().lower(), data_class.strip())


def breach_severity(data_classes: list[str], password_risk: str = "unknown") -> Severity:
    lowered = [d.lower() for d in data_classes]

    def has(*needles: str) -> bool:
        return any(n in d for d in lowered for n in needles)

    has_password = any(d.startswith("password") and "hint" not in d for d in lowered)
    if has(*_CRITICAL) or (has_password and password_risk in ("plaintext", "easytocrack")):
        return Severity.CRITIQUE
    if has_password or has("password hint", "private message"):
        return Severity.ELEVE

    identity_count = sum(has(n) for n in _IDENTITY)
    if identity_count >= 3:
        return Severity.ELEVE
    if identity_count >= 1:
        return Severity.MOYEN
    return Severity.FAIBLE


def breach_tags(data_classes: list[str]) -> list[str]:
    lowered = " ".join(data_classes).lower()
    tags = ["phishing"]
    if "password" in lowered:
        tags.insert(0, "password")
    if "auth token" in lowered:
        tags.insert(0, "token")
    if any(n in lowered for n in ("credit card", "bank account", "payment")):
        tags.insert(0, "financial")
    if any(n in lowered for n in ("social security", "government issued", "passport")):
        tags.insert(0, "identity")
    if any(n in lowered for n in ("phone number", "physical address", "date of birth", "dates of birth")):
        tags.append("contact")
    return tags


_WEIGHTS = {
    Severity.CRITIQUE: 0.50, Severity.ELEVE: 0.30, Severity.MOYEN: 0.12,
    Severity.FAIBLE: 0.04, Severity.INFO: 0.0,
}


def exposure_score(findings: list[Finding]) -> int:
    """Score 0-100 : chaque constat ajoute un risque pondéré par sa confiance, sans dépasser 100."""
    remaining = 1.0
    for finding in findings:
        remaining *= 1 - _WEIGHTS[finding.severity] * finding.confidence / 100
    return round((1 - remaining) * 100)


def score_label(score: int) -> str:
    if score >= 75:
        return "CRITIQUE"
    if score >= 50:
        return "ÉLEVÉ"
    if score >= 25:
        return "MOYEN"
    return "FAIBLE"
