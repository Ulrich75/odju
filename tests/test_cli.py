import pytest

from odju.cli import main
from odju.models import Finding, Report, Severity
from odju.storage import load_report, save_report, to_markdown


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    return tmp_path


def sample():
    finding = Finding(id="F1", kind="breach", title="Fuite | Acme", source="s", severity=Severity.ELEVE,
                      confidence=90, tags=["password"])
    return Report(target_masked="j***@example.com", target_kind="email", consent="self", findings=[finding])


def test_scan_without_consent_is_refused_when_not_interactive(capsys, isolated):
    assert main(["--no-ai", "scan", "jean@example.com"]) == 2
    assert not (isolated / "odju" / "latest.json").exists()


def test_report_files_are_private(isolated):
    save_report(sample())
    assert (isolated / "odju" / "latest.json").stat().st_mode & 0o077 == 0
    assert load_report().findings[0].id == "F1"


def test_fix_and_info_work_offline(capsys):
    save_report(sample())
    assert main(["--no-ai", "fix", "f1"]) == 0
    assert "gestionnaire de mots de passe" in capsys.readouterr().out
    assert main(["--no-ai", "info", "F9"]) == 0
    assert "inconnu" in capsys.readouterr().out


def test_export_markdown_escapes_pipes():
    assert "Fuite \\| Acme" in to_markdown(sample())


def test_banner_is_pure_ascii_and_aligned():
    from odju.render import BANNER_EYE, BANNER_NAME

    assert all(line.isascii() for line in (*BANNER_NAME, BANNER_EYE))
    assert len({len(line) for line in BANNER_NAME}) == 1
    # Largeurs de même parité : l'oeil tombe exactement au milieu du nom.
    assert (len(BANNER_NAME[0]) - len(BANNER_EYE)) % 2 == 0
    assert len(BANNER_EYE) < len(BANNER_NAME[0])


def test_banner_stays_out_of_piped_output(capsys):
    save_report(sample())
    main(["--no-ai", "plan"])
    assert "(@)" not in capsys.readouterr().out
