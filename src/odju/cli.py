"""Interface console : commandes directes et mode interactif."""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path

from rich.text import Text

from odju import ai as ai_module
from odju.ai import AI, AIError
from odju.models import Report, Severity
from odju.render import console, show_banner, show_fix, show_info, show_list, show_plan, show_summary
from odju.scanner import scan
from odju.storage import export_report, load_report, log_consent, save_report
from odju.target import InvalidTarget, Target, parse_target

HELP = """Commandes :
  scan <email | "Prénom Nom">   lancer une analyse
  list [--all] [--min NIVEAU]   lister les constats (NIVEAU : critique, eleve, moyen, faible)
  info <ID>                     détail d'un constat et du risque
  fix <ID>                      correctif recommandé
  plan                          plan d'action priorisé
  export <fichier.md|.json>     exporter le rapport
  help                          afficher cette aide
  quit                          quitter"""

MIN_LEVELS = {
    "critique": Severity.CRITIQUE, "eleve": Severity.ELEVE, "élevé": Severity.ELEVE,
    "moyen": Severity.MOYEN, "faible": Severity.FAIBLE, "info": Severity.INFO,
}


def confirm_consent(target: Target, declared: str | None) -> str | None:
    if declared:
        return declared
    if not sys.stdin.isatty():
        console.print("Mode non interactif : précisez --consent self ou --consent authorized.")
        return None
    console.print(Text(f"Cible : {target.masked}", style="bold"))
    console.print("Cet outil sert à auditer votre propre exposition, ou celle d'une personne qui vous a donné son accord.")
    console.print("  1. C'est mon identité\n  2. J'ai l'accord explicite de cette personne\n  3. Annuler")
    choice = input("Votre choix [3] : ").strip()
    return {"1": "self", "2": "authorized"}.get(choice)


class App:
    def __init__(self, use_ai: bool = True):
        self.ai: AI | None = AI() if use_ai and ai_module.has_credentials() else None
        self.report: Report | None = load_report()

    def scan(self, raw_target: str, declared_consent: str | None = None) -> bool:
        try:
            target = parse_target(raw_target)
        except InvalidTarget as exc:
            console.print(Text(str(exc), style="red"))
            return False
        consent = confirm_consent(target, declared_consent)
        if consent is None:
            console.print("Analyse annulée.")
            return False
        log_consent(target.masked, consent)
        if self.ai is None:
            console.print(Text("IA inactive : analyse par règles, sans recherche web.", style="yellow"))

        with console.status("Analyse des sources…") as status:
            self.report = scan(target, consent, self.ai, progress=status.update)
        save_report(self.report)
        show_summary(self.report)
        show_list(self.report)
        return True

    def _require_report(self) -> Report | None:
        if self.report is None:
            console.print("Aucun rapport : lancez d'abord « scan ».")
        return self.report

    def _finding(self, finding_id: str):
        report = self._require_report()
        if report is None:
            return None
        finding = report.find(finding_id)
        if finding is None:
            console.print(Text(f"Constat inconnu : {finding_id}", style="red"))
        return finding

    def list(self, show_all: bool, minimum: str) -> None:
        if report := self._require_report():
            show_summary(report)
            show_list(report, show_all, MIN_LEVELS[minimum])

    def info(self, finding_id: str) -> None:
        if finding := self._finding(finding_id):
            show_info(finding)

    def fix(self, finding_id: str) -> None:
        finding = self._finding(finding_id)
        if finding is None:
            return
        ai_text = None
        if self.ai is not None:
            try:
                with console.status("Préparation du correctif personnalisé…"):
                    ai_text = self.ai.advise(finding)
            except AIError as exc:
                console.print(Text(f"IA indisponible ({exc}) : conseils standards affichés.", style="yellow"))
        show_fix(finding, ai_text)

    def plan(self) -> None:
        if report := self._require_report():
            show_plan(report)

    def export(self, path: str) -> None:
        if report := self._require_report():
            export_report(report, Path(path))
            console.print(Text(f"Rapport exporté : {path}", style="green"))

    def shell(self) -> None:
        console.print(Text("Tapez « help » pour l'aide.", style="bold"))
        while True:
            try:
                line = input("odju> ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                return
            if line in ("quit", "exit", "q"):
                return
            if line:
                self._dispatch(line)

    def _dispatch(self, line: str) -> None:
        try:
            command, *args = shlex.split(line)
        except ValueError:
            console.print("Commande invalide : guillemet non fermé.")
            return

        if command == "help":
            console.print(Text(HELP))
        elif command == "scan" and args:
            self.scan(" ".join(args))
        elif command == "list":
            minimum = args[args.index("--min") + 1] if "--min" in args[:-1] else "info"
            if minimum not in MIN_LEVELS:
                console.print(Text(f"Niveau inconnu : {minimum}", style="red"))
                return
            self.list("--all" in args, minimum)
        elif command == "info" and len(args) == 1:
            self.info(args[0])
        elif command == "fix" and len(args) == 1:
            self.fix(args[0])
        elif command == "plan":
            self.plan()
        elif command == "export" and len(args) == 1:
            self.export(args[0])
        else:
            console.print(Text("Commande non reconnue. Tapez « help ».", style="red"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="odju", description="Audit d'exposition numérique assisté par IA.")
    parser.add_argument("--no-ai", action="store_true", help="n'envoie rien à l'IA (règles locales uniquement)")
    commands = parser.add_subparsers(dest="command")

    scan_parser = commands.add_parser("scan", help="analyser un email ou un nom")
    scan_parser.add_argument("target", nargs="+", help='email ou "Prénom Nom"')
    scan_parser.add_argument("--consent", choices=["self", "authorized"], help="base de l'analyse")
    list_parser = commands.add_parser("list", help="lister les constats du dernier rapport")
    list_parser.add_argument("--all", action="store_true")
    list_parser.add_argument("--min", default="info", choices=sorted(MIN_LEVELS))
    commands.add_parser("info", help="détail d'un constat").add_argument("id")
    commands.add_parser("fix", help="correctif d'un constat").add_argument("id")
    commands.add_parser("plan", help="plan d'action")
    commands.add_parser("export", help="exporter le rapport").add_argument("path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    app = App(use_ai=not args.no_ai)

    if args.command in (None, "scan") and console.is_terminal:
        show_banner()

    if args.command is None:
        app.shell()
    elif args.command == "scan":
        if not app.scan(" ".join(args.target), args.consent):
            return 2
        if sys.stdin.isatty():
            app.shell()
    elif args.command == "list":
        app.list(args.all, args.min)
    elif args.command == "info":
        app.info(args.id)
    elif args.command == "fix":
        app.fix(args.id)
    elif args.command == "plan":
        app.plan()
    elif args.command == "export":
        app.export(args.path)
    return 0
