"""Fait passer les appels par le vrai SDK, avec un transport simulé."""

import json
from types import SimpleNamespace as NS

import anthropic
import httpx2
import pytest

from odju.ai import AI, AIError, Mention, _final_text, _search_result_urls
from odju.models import Assessment, Finding, Report, Severity


def message(content, stop_reason="end_turn"):
    return {
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
        "content": content, "stop_reason": stop_reason, "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }


def ai_with(handler):
    client = anthropic.Anthropic(
        api_key="test", max_retries=0,
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler)),
    )
    return AI(client)


FINDING = Finding(id="F1", kind="breach", title="Fuite", source="s", severity=Severity.ELEVE, confidence=90)
REPORT = Report(target_masked="j***@example.com", target_kind="email", consent="self", findings=[FINDING])


def test_assess_sends_fallback_and_drops_unknown_ids():
    seen = {}

    def handler(request):
        seen["beta"] = request.headers.get("anthropic-beta", "")
        seen["body"] = json.loads(request.content)
        output = {"summary": "s", "top_risks": ["r"],
                  "plan": [{"action": "a", "why": "w", "finding_ids": ["F1", "F99"]}]}
        return httpx2.Response(200, json=message([{"type": "text", "text": json.dumps(output)}]))

    result = ai_with(handler).assess(REPORT)
    assert isinstance(result, Assessment)
    assert result.plan[0].finding_ids == ["F1"]
    assert "server-side-fallback-2026-07-01" in seen["beta"]
    assert seen["body"]["fallbacks"] == "default"
    assert seen["body"]["model"] == "claude-opus-5-5"
    assert seen["body"]["output_config"]["format"]["type"] == "json_schema"
    assert "j***@example.com" not in json.dumps(seen["body"])


def test_refusal_becomes_ai_error():
    ai = ai_with(lambda r: httpx2.Response(200, json=message([], "refusal")))
    with pytest.raises(AIError):
        ai.advise(FINDING)


def test_auth_error_becomes_ai_error():
    body = {"type": "error", "error": {"type": "authentication_error", "message": "x"}}
    ai = ai_with(lambda r: httpx2.Response(401, json=body))
    with pytest.raises(AIError, match="identifiants"):
        ai.assess(REPORT)


def test_final_text_ignores_abandoned_attempt():
    blocks = [NS(type="text", text="partiel"), NS(type="fallback"), NS(type="text", text="final")]
    assert _final_text(NS(content=blocks)) == "final"


def test_search_result_urls_ignores_error_blocks():
    blocks = [
        NS(type="web_search_tool_result", content=[NS(url="https://a.test/")]),
        NS(type="web_search_tool_result", content=NS(error_code="max_uses_exceeded")),
    ]
    assert _search_result_urls(blocks) == {"https://a.test"}


def test_invented_urls_are_dropped():
    tool_input = {"mentions": [
        Mention(title="vraie", url="https://a.test", category="forum", exposed=[], confidence=50, summary="").model_dump(),
        Mention(title="inventée", url="https://b.test", category="forum", exposed=[], confidence=50, summary="").model_dump(),
    ]}
    final = NS(
        stop_reason="tool_use",
        content=[
            NS(type="web_search_tool_result", content=[NS(url="https://a.test")]),
            NS(type="tool_use", name="record_mentions", input=tool_input),
        ],
    )

    class Stream:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def get_final_message(self):
            return final

    fake = NS(beta=NS(messages=NS(stream=lambda **_: Stream())))
    assert [m.title for m in AI(fake).search_mentions("Jean Dupont")] == ["vraie"]
