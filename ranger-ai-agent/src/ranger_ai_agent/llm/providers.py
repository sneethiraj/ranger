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

"""HTTP providers for OpenAI-compatible and Ollama chat endpoints.

Each provider sends a system and user message and returns the raw text of the
reply. Parsing and validation happen in explain.py.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlparse

import requests

from ranger_ai_agent.llm.explain import Prompt

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
DEFAULT_OLLAMA_URL = "http://localhost:11434"


class LLMError(RuntimeError):
    """The provider could not return a usable reply."""


def _is_local(base_url: str) -> bool:
    return (urlparse(base_url).hostname or "") in _LOCAL_HOSTS


class _HttpProvider:
    name = "http"

    def __init__(self, base_url: str, model: str, timeout: float = 60.0, session: Optional[requests.Session] = None) -> None:
        if not model:
            raise ValueError("a model name is required")
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout
        self._session = session or requests.Session()

    @property
    def external(self) -> bool:
        return not _is_local(self._base_url)

    def _post(self, path: str, body: Dict[str, Any], headers: Optional[Mapping[str, str]] = None) -> Any:
        try:
            response = self._session.post(self._base_url + path, json=body, headers=dict(headers or {}), timeout=self._timeout)
        except requests.RequestException as exc:
            # Report the exception type only; its message may echo request details.
            raise LLMError("request failed: %s" % type(exc).__name__) from exc
        if response.status_code != 200:
            raise LLMError("HTTP %d from model endpoint" % response.status_code)
        try:
            return response.json()
        except ValueError as exc:
            raise LLMError("model endpoint returned non-JSON") from exc

    @staticmethod
    def _messages(prompt: Prompt) -> list:
        return [
            {"role": "system", "content": prompt.system},
            {"role": "user", "content": prompt.user},
        ]


class OpenAICompatibleProvider(_HttpProvider):
    name = "openai-compatible"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: Optional[str] = None,
        timeout: float = 60.0,
        session: Optional[requests.Session] = None,
    ) -> None:
        super().__init__(base_url, model, timeout, session)
        self._api_key = api_key

    def complete_json(self, prompt: Prompt) -> str:
        headers = {"Authorization": "Bearer " + self._api_key} if self._api_key else {}
        body = {
            "model": self._model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": self._messages(prompt),
        }
        data = self._post("/chat/completions", body, headers)
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError("unexpected response shape from model endpoint") from exc


class OllamaProvider(_HttpProvider):
    name = "ollama"

    def __init__(
        self,
        model: str,
        base_url: str = DEFAULT_OLLAMA_URL,
        timeout: float = 120.0,
        session: Optional[requests.Session] = None,
    ) -> None:
        super().__init__(base_url, model, timeout, session)

    def complete_json(self, prompt: Prompt) -> str:
        body = {
            "model": self._model,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
            "messages": self._messages(prompt),
        }
        data = self._post("/api/chat", body)
        try:
            return data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise LLMError("unexpected response shape from model endpoint") from exc


ALLOW_EXTERNAL_ENV = "RANGER_AI_ALLOW_EXTERNAL_LLM"


def _truthy(value: Optional[str]) -> bool:
    return value is not None and value.strip().lower() in ("1", "true", "yes", "on")


def provider_from_env(environ: Optional[Mapping[str, str]] = None):
    """Return the configured provider, or None when no model is configured.

    RANGER_AI_LLM_PROVIDER: none (default), openai, or ollama
    RANGER_AI_LLM_URL, RANGER_AI_LLM_MODEL, RANGER_AI_LLM_API_KEY (openai only)

    A non-local endpoint sends (pseudonymized) finding data off this host, so it
    is refused unless RANGER_AI_ALLOW_EXTERNAL_LLM is set to a true value.
    """
    env = os.environ if environ is None else environ
    mode = env.get("RANGER_AI_LLM_PROVIDER", "none").strip().lower()
    if mode == "none":
        return None
    if mode == "openai":
        provider = OpenAICompatibleProvider(
            base_url=env.get("RANGER_AI_LLM_URL", ""),
            model=env.get("RANGER_AI_LLM_MODEL", ""),
            api_key=env.get("RANGER_AI_LLM_API_KEY") or None,
        )
    elif mode == "ollama":
        provider = OllamaProvider(
            model=env.get("RANGER_AI_LLM_MODEL", ""),
            base_url=env.get("RANGER_AI_LLM_URL", DEFAULT_OLLAMA_URL),
        )
    else:
        raise ValueError("unknown RANGER_AI_LLM_PROVIDER: %r" % mode)

    if provider.external and not _truthy(env.get(ALLOW_EXTERNAL_ENV)):
        raise ValueError(
            "the model endpoint is not local; set %s=1 to allow sending pseudonymized finding data to it"
            % ALLOW_EXTERNAL_ENV
        )
    return provider
