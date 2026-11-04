"""Affichage console. Les données externes passent par Text pour ne jamais être lues comme du balisage."""

from __future__ import annotations

from collections import Counter

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from odju import __version__
from odju.models import Finding, Report, Severity
from odju.remediation import advice_for
from odju.scoring import score_label

console = Console()

STYLES = {
    Severity.CRITIQUE: "bold white on red", Severity.ELEVE: "bold red", Severity.MOYEN: "yellow",
    Severity.FAIBLE: "cyan", Severity.INFO: "dim",
}
STATE_LABELS = {"ok": ("OK", "green"), "skipped": ("ignorée", "yellow"), "error": ("ÉCHEC", "bold red")}
DEFAULT_LIMIT = 15

# De l'ASCII pur, car la largeur des emojis varie selon les terminaux.
BANNER_NAME = (
    r"  ___  ____      _ _   _ ",
    r" / _ \|  _ \    | | | | |",
    r"| | | | | | |_  | | | | |",
    r"| |_| | |_| | |_| | |_| |",
    r" \___/|____/ \___/ \___/ ",
)
BANNER_EYE = "<(@)>"
BANNER_DESCRIPTION = (
    "Audit d'exposition numérique assisté par IA.\n"
    "À partir d'un email ou d'un nom, odju indique où une identité est exposée en ligne, "
    "avec la source, la criticité et le niveau de confiance, puis explique comment corriger."
)
AUTHOR = "Ulrich"


def show_banner() -> None:
    width = len(BANNER_NAME[0])
    banner = Text(no_wrap=True, overflow="crop")
    for line in BANNER_NAME:
        banner.append(line + "\n", style="bold cyan")
    banner.append(BANNER_EYE.center(width), style="bold red")
    console.print(Align.center(banner))
    console.print()
    console.print(Text(BANNER_DESCRIPTION), justify="center")
    console.print()
    console.print(Text(f"Développé par {AUTHOR} · v{__version__}", style="dim"), justify="center")


def severity_text(severity: Severity) -> Text:
    return Text(f" {severity.label} ", style=STYLES[severity])


def show_summary(report: Report) -> None:
    counts = Counter(f.severity for f in report.findings)
    header = Text.assemble(
        ("Identité : ", "bold"), report.target_masked, "\n",
        ("Score d'exposition : ", "bold"), (f"{report.exposure_score}/100", "bold"),
        f"  ({score_label(report.exposure_score)})\n",
        ("Constats : ", "bold"), str(len(report.findings)), "  ",
    )
    for severity in sorted(Severity, reverse=True):
        if counts[severity]:
            header.append(f"{severity.label} {counts[severity]}  ", style=STYLES[severity])
    console.print(Panel(header, title="odju", border_style="blue"))
    show_sources(report)
    if report.assessment:
        console.print(Panel(Text(report.assessment.summary), title="Synthèse IA", border_style="magenta"))


def show_sources(report: Report) -> None:
    table = Table(title="Sources interrogées", title_justify="left", box=None, pad_edge=False)
    for column in ("Source", "État", "Résultats", "Détail"):
        table.add_column(column)
    for status in report.sources:
        label, style = STATE_LABELS[status.state]
        table.add_row(Text(status.name), Text(label, style=style), str(status.count), Text(status.message))
    console.print(table)
    if report.is_partial:
        console.print(Text(
            "Couverture partielle : un résultat vide sur ces sources ne prouve pas l'absence d'exposition.",
            style="yellow",
        ))


def show_list(report: Report, show_all: bool = False, minimum: Severity = Severity.INFO) -> None:
    findings = [f for f in report.findings if f.severity >= minimum]
    if not findings:
        console.print("Aucun constat sur les sources disponibles.")
        return
    shown = findings if show_all else findings[:DEFAULT_LIMIT]

    table = Table(expand=True)
    table.add_column("ID", no_wrap=True)
    table.add_column("Criticité", no_wrap=True)
    table.add_column("Conf.", justify="right", no_wrap=True)
    table.add_column("Constat", ratio=3)
    table.add_column("Données exposées", ratio=3)
    table.add_column("Source", ratio=2)
    for f in shown:
        table.add_row(
            f.id, severity_text(f.severity), f"{f.confidence} %",
            Text(f.title), Text(", ".join(f.exposed[:5])), Text(f.source),
        )
    console.print(table)
    if len(shown) < len(findings):
        console.print(Text(f"{len(findings) - len(shown)} autres constats : tapez « list --all ».", style="dim"))
    console.print(Text("« info F1 » pour le détail, « fix F1 » pour le correctif, « plan » pour le plan d'action.", style="dim"))


def show_info(finding: Finding) -> None:
    body = Text()
    body.append("Criticité : ", style="bold")
    body.append_text(severity_text(finding.severity))
    body.append("\nConfiance : ", style="bold")
    body.append(f"{finding.confidence} %  ")
    body.append(finding.confidence_reason, style="dim")
    body.append("\nSource : ", style="bold")
    body.append(finding.source)
    if finding.source_url:
        body.append("\nLien : ", style="bold")
        body.append(finding.source_url)
    if finding.date:
        body.append("\nDate : ", style="bold")
        body.append(finding.date)
    if finding.exposed:
        body.append("\nDonnées exposées : ", style="bold")
        body.append(", ".join(finding.exposed))
    if finding.summary:
        body.append("\n\n")
        body.append(finding.summary)
    risks = [advice.risk for advice in advice_for(finding)]
    if risks:
        body.append("\n\nPourquoi c'est un risque :", style="bold")
        for risk in risks:
            body.append(f"\n- {risk}")
    console.print(Panel(body, title=Text(f"{finding.id} · {finding.title}"), border_style="blue"))


def show_fix(finding: Finding, ai_text: str | None = None) -> None:
    body = Text()
    if ai_text:
        body.append("Analyse personnalisée (IA)\n", style="bold magenta")
        body.append(ai_text)
        body.append("\n\n")
    body.append("Étapes recommandées\n", style="bold")
    steps = list(dict.fromkeys(step for advice in advice_for(finding) for step in advice.steps))
    for number, step in enumerate(steps, start=1):
        body.append(f"{number}. {step}\n")
    console.print(Panel(body, title=Text(f"Correctif {finding.id} · {finding.title}"), border_style="green"))


def show_plan(report: Report) -> None:
    if report.assessment:
        table = Table(title="Plan d'action", title_justify="left", expand=True)
        table.add_column("#", no_wrap=True)
        table.add_column("Action", ratio=3)
        table.add_column("Pourquoi", ratio=3)
        table.add_column("Constats", ratio=1)
        for number, step in enumerate(report.assessment.plan, start=1):
            table.add_row(str(number), Text(step.action), Text(step.why), Text(", ".join(step.finding_ids)))
        console.print(table)
        return

    grouped: dict[str, list[str]] = {}
    order: list[tuple[str, list[str]]] = []
    for finding in report.findings:
        for advice in advice_for(finding):
            if advice.risk not in grouped:
                grouped[advice.risk] = []
                order.append((advice.risk, grouped[advice.risk]))
            grouped[advice.risk].append(finding.id)
    if not order:
        console.print("Aucune action nécessaire sur les sources disponibles.")
        return
    console.print(Text("Plan d'action (règles hors ligne, du plus grave au moins grave)", style="bold"))
    for number, (risk, ids) in enumerate(order, start=1):
        suffix = f" ({', '.join(ids[:5])}{'…' if len(ids) > 5 else ''})"
        console.print(Text(f"{number}. {risk}{suffix}"))
    console.print(Text("Tapez « fix <ID> » pour les étapes détaillées.", style="dim"))
