import httpx
import pytest

from odju.models import Severity
from odju.scanner import _run_source
from odju.sources import dns_records, github, gravatar, hibp, xposedornot
from odju.sources.errors import SourceFailed, SourceSkipped
from odju.target import parse_target

EMAIL = parse_target("jean@example.com")


def client_for(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


BREACH = {
    "breach": "Acme", "domain": "acme.test", "verified": "Yes", "password_risk": "plaintext",
    "xposed_data": "Email addresses;Passwords", "xposed_date": "2020", "details": "Fuite Acme",
}


def test_xposedornot_maps_a_breach():
    client = client_for(lambda r: httpx.Response(200, json={"ExposedBreaches": {"breaches_details": [BREACH]}}))
    finding = xposedornot.check(EMAIL, client)[0]
    assert finding.severity == Severity.CRITIQUE
    assert finding.confidence == 95
    assert finding.exposed == ["adresses email", "mots de passe"]
    assert "password" in finding.tags


def test_xposedornot_handles_null_for_clean_address():
    client = client_for(lambda r: httpx.Response(200, json={"ExposedBreaches": None}))
    assert xposedornot.check(EMAIL, client) == []


def test_server_error_is_a_failure_not_an_empty_result():
    client = client_for(lambda r: httpx.Response(503))
    status, findings = _run_source("XposedOrNot", xposedornot.check, EMAIL, client)
    assert status.state == "error"
    assert findings == []


def test_network_error_is_reported():
    def boom(request):
        raise httpx.ConnectTimeout("timeout")

    status, _ = _run_source("Gravatar", gravatar.check, EMAIL, client_for(boom))
    assert status.state == "error"


def test_hibp_is_skipped_without_key(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    with pytest.raises(SourceSkipped):
        hibp.check(EMAIL, client_for(lambda r: httpx.Response(200, json=[])))


def test_hibp_sends_key_and_strips_html(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")

    def handler(request):
        assert request.headers["hibp-api-key"] == "k"
        assert "jean%40example.com" in str(request.url)
        return httpx.Response(200, json=[{
            "Title": "Acme", "DataClasses": ["Passwords"], "IsVerified": True,
            "Description": "<a href='x'>Acme</a> a fuité", "BreachDate": "2020-01-01",
        }])

    finding = hibp.check(EMAIL, client_for(handler))[0]
    assert finding.summary == "Acme a fuité"


def test_github_rate_limit_is_a_failure():
    with pytest.raises(SourceFailed):
        github.check(EMAIL, client_for(lambda r: httpx.Response(403)))


def test_github_name_match_stays_low_confidence():
    def handler(request):
        if "search/users" in str(request.url):
            return httpx.Response(200, json={"items": [{"login": "jd", "html_url": "https://github.com/jd"}]})
        return httpx.Response(200, json={"name": "Jean DUPONT", "location": "Lyon"})

    finding = github.check(parse_target("Jean Dupont"), client_for(handler))[0]
    assert finding.confidence <= 50
    assert "homonym" in finding.tags


def test_dns_skips_public_providers():
    with pytest.raises(SourceSkipped):
        dns_records.check(parse_target("a@gmail.com"), client_for(lambda r: httpx.Response(200)))


@pytest.mark.parametrize(
    "records, expected",
    [
        ({"example.com": ["v=spf1 -all"], "_dmarc.example.com": ["v=DMARC1; p=reject"]}, []),
        ({"example.com": ["v=spf1 -all"], "_dmarc.example.com": ["v=DMARC1; p=none"]}, [Severity.FAIBLE]),
        ({"example.com": [], "_dmarc.example.com": []}, [Severity.MOYEN, Severity.MOYEN]),
    ],
)
def test_dns_rules(monkeypatch, records, expected):
    monkeypatch.setattr(dns_records, "_txt", lambda name: records[name])
    findings = dns_records.check(EMAIL, client_for(lambda r: httpx.Response(200)))
    assert [f.severity for f in findings] == expected
