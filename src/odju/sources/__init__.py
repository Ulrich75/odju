"""Connecteurs de données. Chaque source reçoit la cible et renvoie des constats bruts."""

from __future__ import annotations

from collections.abc import Callable

import httpx

from odju.models import Finding
from odju.sources import dns_records, github, gravatar, hibp, xposedornot
from odju.target import Target

Check = Callable[[Target, httpx.Client], list[Finding]]

# (nom, types de cible acceptés, fonction)
SOURCES: list[tuple[str, tuple[str, ...], Check]] = [
    ("Have I Been Pwned", ("email",), hibp.check),
    ("XposedOrNot", ("email",), xposedornot.check),
    ("Gravatar", ("email",), gravatar.check),
    ("GitHub", ("email", "name"), github.check),
    ("DNS du domaine", ("email",), dns_records.check),
]
