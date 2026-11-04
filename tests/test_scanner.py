from odju.ai import Mention
from odju.models import Finding, Severity, clean
from odju.scanner import mention_to_finding, merge_duplicates
from odju.target import parse_target


def breach(source, severity, exposed):
    return Finding(kind="breach", title="Fuite de données : Acme", source=source,
                   severity=severity, confidence=90, exposed=exposed)


def mention(confidence=99, category="courtier_donnees"):
    return Mention(title="Page", url="https://a.test", category=category,
                   exposed=["téléphone"], confidence=confidence, summary="s")


def test_same_breach_from_two_sources_is_merged():
    merged = merge_duplicates([breach("HIBP", Severity.ELEVE, ["a"]), breach("XON", Severity.CRITIQUE, ["b"])])
    assert len(merged) == 1
    assert merged[0].severity == Severity.CRITIQUE
    assert merged[0].exposed == ["a", "b"]
    assert merged[0].source == "HIBP + XON"


def test_ai_confidence_is_capped_and_cannot_decide_severity():
    finding = mention_to_finding(mention(), parse_target("Jean Dupont"))
    assert finding.confidence == 70
    assert finding.severity == Severity.ELEVE
    assert "homonym" in finding.tags


def test_control_sequences_are_removed():
    assert clean("ok\x1b[31m\x07") == "ok[31m"
    finding = Finding(kind="breach", title="a\x1b]0;x\x07b", source="s", severity=Severity.INFO, confidence=1)
    assert "\x1b" not in finding.title
