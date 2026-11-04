"""Analyse et masquage de la cible."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Literal

_EMAIL = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
_NAME = re.compile(r"^[^\W\d_]+(?:[ '’-][^\W\d_]+)+$")


class InvalidTarget(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    raw: str
    kind: Literal["email", "name"]

    @property
    def domain(self) -> str:
        return self.raw.rsplit("@", 1)[1] if self.kind == "email" else ""

    @property
    def masked(self) -> str:
        if self.kind == "email":
            local, domain = self.raw.split("@", 1)
            return f"{local[0]}***@{domain}"
        return " ".join(f"{part[0]}***" for part in self.raw.split())


def parse_target(value: str) -> Target:
    value = " ".join(value.split())
    if _EMAIL.match(value):
        return Target(value.lower(), "email")
    if _NAME.match(value):
        return Target(value, "name")
    raise InvalidTarget("Indiquez un email valide, ou un prénom et un nom (au moins deux mots).")


def normalize_name(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value)
    ascii_only = "".join(c for c in decomposed if not unicodedata.combining(c))
    return " ".join(ascii_only.casefold().split())
