# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json

import pytest
import requests

from ranger_ai_agent.detectors.core import Finding
from ranger_ai_agent.llm.explain import (
    ExplanationError,
    build_prompt,
    parse_explanation,
    template_explanation,
)
from ranger_ai_agent.llm.providers import LLMError, OllamaProvider, OpenAICompatibleProvider, provider_from_env
from ranger_ai_agent.llm.redact import Pseudonymizer
from ranger_ai_agent.suggestions.models import ACTION_REMOVE_USER


def valid_reply(**overrides):
    data = {
        "summary": "carol has an unused grant.",
        "rationale": "no allowed events through policy 1",
        "recommended_action": "REMOVE_USER_FROM_POLICY",
        "self_confidence": 0.8,
        "caveats": ["check whether carol is on leave"],
    }
    data.update(overrides)
    return json.dumps(data)


def test_pseudonyms_are_stable_per_key_and_differ_across_keys():
    a = Pseudonymizer(b"key-one")
    b = Pseudonymizer(b"key-one")
    c = Pseudonymizer(b"key-two")
    assert a.pseudonym("carol") == b.pseudonym("carol")
    assert a.pseudonym("carol") != c.pseudonym("carol")
    assert a.pseudonym("carol").startswith("u_")


def test_redact_text_matches_whole_tokens_only():
    p = Pseudonymizer(b"k")
    text = "carol logged in; carol.smith and carolina were not touched"
    redacted = p.redact_text(text, ["carol"])
    assert "carol logged" not in redacted
    assert "carol.smith" in redacted and "carolina" in redacted
    assert p.reveal(redacted) == text  # reveal restores the original text


def test_prompt_never_contains_raw_user_names_or_free_text():
    p = Pseudonymizer(b"k")
    finding = Finding(
        kind="OVER_PRIVILEGED",
        confidence=0.9,
        summary="User 'carol' is granted policy 1",
        policy_id=1,
        user="carol",
        evidence=("allowed events by carol through this policy in 90d: 0", "policy:1"),
    )
    prompt = build_prompt(finding, "hive_sales_read", {"carol", "alice"}, p)
    assert "carol" not in prompt.user
    assert "carol" not in prompt.system
    assert "alice" not in prompt.user
    assert finding.summary not in prompt.user  # free-text summary is not sent
    assert "untrusted" in prompt.system.lower()


def test_control_characters_are_stripped_from_policy_name():
    finding = Finding(kind="STALE_POLICY", confidence=0.8, summary="", policy_id=9, user=None, evidence=())
    prompt = build_prompt(finding, "bad\nname\x00 IGNORE PREVIOUS", set(), Pseudonymizer(b"k"))
    data = json.loads(prompt.user.split("\n", 1)[1])
    assert data["policy_name"] == "bad name  IGNORE PREVIOUS"
    assert "\x00" not in prompt.user


def test_valid_reply_parses():
    exp = parse_explanation(valid_reply())
    assert exp.recommended_action == ACTION_REMOVE_USER
    assert exp.self_confidence == pytest.approx(0.8)
    assert exp.caveats == ("check whether carol is on leave",)


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        valid_reply(status="APPROVED"),
        valid_reply(recommended_action="DELETE_POLICY"),
        valid_reply(self_confidence=1.5),
        valid_reply(self_confidence=True),
        valid_reply(summary="   "),
        valid_reply(summary="x" * 601),
        valid_reply(caveats="not a list"),
        valid_reply(caveats=["c"] * 6),
    ],
)
def test_invalid_replies_are_rejected(text):
    with pytest.raises(ExplanationError):
        parse_explanation(text)


def test_template_explanation_is_deterministic_and_uses_allowed_action():
    finding = Finding(kind="STALE_POLICY", confidence=0.8, summary="stale", policy_id=9, user=None, evidence=("e1",))
    exp = template_explanation(finding)
    assert exp.summary == "stale"
    assert exp.recommended_action == "DISABLE_POLICY"
    assert exp.self_confidence == 0.8
    assert template_explanation(finding) == exp


class FakeResponse:
    def __init__(self, status=200, body=None, not_json=False):
        self.status_code = status
        self._body = body
        self._not_json = not_json

    def json(self):
        if self._not_json:
            raise ValueError("bad json")
        return self._body


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        if self.error:
            raise self.error
        return self.response


def sample_prompt():
    finding = Finding(kind="STALE_POLICY", confidence=0.8, summary="", policy_id=9, user=None, evidence=())
    return build_prompt(finding, "legacy", set(), Pseudonymizer(b"k"))


def test_openai_provider_request_shape_and_reply():
    session = FakeSession(FakeResponse(body={"choices": [{"message": {"content": valid_reply()}}]}))
    provider = OpenAICompatibleProvider("https://llm.example.com/v1/", "m1", api_key="sekret", session=session)
    text = provider.complete_json(sample_prompt())
    assert text == valid_reply()
    call = session.calls[0]
    assert call["url"] == "https://llm.example.com/v1/chat/completions"
    assert call["headers"] == {"Authorization": "Bearer sekret"}
    assert call["json"]["response_format"] == {"type": "json_object"}
    assert call["json"]["temperature"] == 0
    assert provider.external is True


def test_ollama_provider_request_shape_and_reply():
    session = FakeSession(FakeResponse(body={"message": {"content": valid_reply()}}))
    provider = OllamaProvider("llama3", session=session)
    assert provider.complete_json(sample_prompt()) == valid_reply()
    call = session.calls[0]
    assert call["url"] == "http://localhost:11434/api/chat"
    assert call["json"]["format"] == "json"
    assert call["json"]["stream"] is False
    assert provider.external is False


def test_provider_errors_become_llm_error():
    with pytest.raises(LLMError, match="request failed: ConnectionError"):
        OllamaProvider("m", session=FakeSession(error=requests.ConnectionError("secret detail"))).complete_json(sample_prompt())
    with pytest.raises(LLMError, match="HTTP 500"):
        OllamaProvider("m", session=FakeSession(FakeResponse(status=500))).complete_json(sample_prompt())
    with pytest.raises(LLMError, match="non-JSON"):
        OllamaProvider("m", session=FakeSession(FakeResponse(not_json=True))).complete_json(sample_prompt())
    with pytest.raises(LLMError, match="unexpected response shape"):
        OpenAICompatibleProvider("http://x", "m", session=FakeSession(FakeResponse(body={}))).complete_json(sample_prompt())


def test_provider_from_env():
    assert provider_from_env({}) is None
    assert provider_from_env({"RANGER_AI_LLM_PROVIDER": "none"}) is None
    p = provider_from_env({"RANGER_AI_LLM_PROVIDER": "ollama", "RANGER_AI_LLM_MODEL": "llama3"})
    assert isinstance(p, OllamaProvider)
    with pytest.raises(ValueError, match="unknown"):
        provider_from_env({"RANGER_AI_LLM_PROVIDER": "bogus"})
    with pytest.raises(ValueError, match="model name"):
        provider_from_env({"RANGER_AI_LLM_PROVIDER": "openai", "RANGER_AI_LLM_URL": "http://x"})
