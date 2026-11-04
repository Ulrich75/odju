import pytest

from odju.target import InvalidTarget, normalize_name, parse_target


def test_email_is_lowercased_and_masked():
    target = parse_target("Jean.Dupont@Example.COM")
    assert target.kind == "email"
    assert target.domain == "example.com"
    assert target.masked == "j***@example.com"


def test_name_accepts_accents_and_hyphens():
    target = parse_target("  Éloïse   Saint-Martin ")
    assert target.kind == "name"
    assert target.raw == "Éloïse Saint-Martin"
    assert target.masked == "É*** S***"


@pytest.mark.parametrize("value", ["jean", "+33612345678", "12 rue de Paris", "a@b", "x; rm -rf /"])
def test_invalid_targets_are_rejected(value):
    with pytest.raises(InvalidTarget):
        parse_target(value)


def test_normalize_name_ignores_accents_and_case():
    assert normalize_name("  ÉLOÏSE  Müller") == "eloise muller"
