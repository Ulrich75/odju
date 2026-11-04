from odju.models import Finding, Severity
from odju.scoring import breach_severity, exposure_score


def finding(severity, confidence=100):
    return Finding(kind="breach", title="x", source="s", severity=severity, confidence=confidence)


def test_clear_password_is_critical():
    assert breach_severity(["Email addresses", "Passwords"], "plaintext") == Severity.CRITIQUE


def test_strong_hash_is_high_not_critical():
    assert breach_severity(["Passwords"], "hardtocrack") == Severity.ELEVE


def test_password_hint_alone_is_high():
    assert breach_severity(["Password hints"]) == Severity.ELEVE


def test_credit_card_is_critical():
    assert breach_severity(["Credit cards"]) == Severity.CRITIQUE


def test_identity_data_accumulates():
    assert breach_severity(["Phone numbers"]) == Severity.MOYEN
    assert breach_severity(["Phone numbers", "Physical addresses", "Dates of birth"]) == Severity.ELEVE


def test_email_only_is_low():
    assert breach_severity(["Email addresses"]) == Severity.FAIBLE


def test_score_bounds_and_confidence_weighting():
    assert exposure_score([]) == 0
    assert exposure_score([finding(Severity.INFO)]) == 0
    assert exposure_score([finding(Severity.CRITIQUE, 100)]) > exposure_score([finding(Severity.CRITIQUE, 20)])
    assert exposure_score([finding(Severity.CRITIQUE)] * 200) == 100
