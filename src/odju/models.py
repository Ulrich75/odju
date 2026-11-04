"""Modèle de données du rapport."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import IntEnum
from typing import Literal

from pydantic import BaseModel, Field, field_validator

# Les données viennent de tiers : on retire tout ce qui pourrait piloter le terminal.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean(value: str) -> str:
    return _CONTROL_CHARS.sub("", value).strip()


class Severity(IntEnum):
    INFO = 0
    FAIBLE = 1
    MOYEN = 2
    ELEVE = 3
    CRITIQUE = 4

    @property
    def label(self) -> str:
        return {4: "CRITIQUE", 3: "ÉLEVÉ", 2: "MOYEN", 1: "FAIBLE", 0: "INFO"}[int(self)]


FindingKind = Literal["breach", "public_profile", "git_history", "domain", "web_mention"]


class Finding(BaseModel):
    id: str = ""
    kind: FindingKind
    title: str
    source: str
    source_url: str = ""
    severity: Severity
    confidence: int = Field(ge=0, le=100, description="Probabilité que le résultat concerne bien la cible")
    confidence_reason: str = ""
    exposed: list[str] = Field(default_factory=list)
    date: str = ""
    summary: str = ""
    tags: list[str] = Field(default_factory=list, description="Clés de correctifs (voir remediation.py)")

    @field_validator("title", "source", "source_url", "confidence_reason", "date", "summary")
    @classmethod
    def _clean_text(cls, value: str) -> str:
        return clean(value)

    @field_validator("exposed")
    @classmethod
    def _clean_list(cls, value: list[str]) -> list[str]:
        return [clean(item) for item in value]


class SourceStatus(BaseModel):
    name: str
    state: Literal["ok", "skipped", "error"]
    message: str = ""
    count: int = 0


class PlanStep(BaseModel):
    action: str
    why: str
    finding_ids: list[str]


class Assessment(BaseModel):
    """Synthèse produite par l'IA (sortie structurée)."""

    summary: str
    top_risks: list[str]
    plan: list[PlanStep]


class Report(BaseModel):
    target_masked: str
    target_kind: Literal["email", "name"]
    consent: Literal["self", "authorized"]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[Finding] = Field(default_factory=list)
    sources: list[SourceStatus] = Field(default_factory=list)
    exposure_score: int = 0
    assessment: Assessment | None = None

    def find(self, finding_id: str) -> Finding | None:
        wanted = finding_id.upper()
        return next((f for f in self.findings if f.id == wanted), None)

    @property
    def is_partial(self) -> bool:
        return any(s.state != "ok" for s in self.sources)
