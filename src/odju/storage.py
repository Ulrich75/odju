"""Stockage local : dernier rapport (identité masquée) et journal d'audit."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from odju.models import Report


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    path = Path(base) / "odju"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def _write_private(path: Path, content: str, mode: str = "w") -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | (os.O_APPEND if mode == "a" else os.O_TRUNC), 0o600)
    with os.fdopen(descriptor, mode, encoding="utf-8") as handle:
        handle.write(content)


def save_report(report: Report) -> None:
    _write_private(data_dir() / "latest.json", report.model_dump_json(indent=1))


def load_report() -> Report | None:
    path = data_dir() / "latest.json"
    return Report.model_validate_json(path.read_text(encoding="utf-8")) if path.exists() else None


def log_consent(masked_target: str, consent: str) -> None:
    entry = {
        "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cible": masked_target,
        "base": consent,
    }
    _write_private(data_dir() / "audit.log", json.dumps(entry, ensure_ascii=False) + "\n", "a")


def to_markdown(report: Report) -> str:
    lines = [
        f"# Rapport d'exposition : {report.target_masked}",
        "",
        f"- Date : {report.created_at:%Y-%m-%d %H:%M} UTC",
        f"- Score d'exposition : {report.exposure_score}/100",
        f"- Constats : {len(report.findings)}",
    ]
    if report.is_partial:
        lines.append("- Couverture partielle : certaines sources n'ont pas été interrogées.")
    if report.assessment:
        lines += ["", "## Synthèse", "", report.assessment.summary]
    lines += ["", "## Constats", "", "| ID | Criticité | Confiance | Constat | Source |", "|---|---|---|---|---|"]
    for f in report.findings:
        title = f.title.replace("|", "\\|")
        lines.append(f"| {f.id} | {f.severity.label} | {f.confidence} % | {title} | {f.source_url or f.source} |")
    return "\n".join(lines) + "\n"


def export_report(report: Report, path: Path) -> None:
    content = report.model_dump_json(indent=2) if path.suffix == ".json" else to_markdown(report)
    _write_private(path, content)
