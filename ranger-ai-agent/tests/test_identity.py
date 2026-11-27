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

import pytest
import requests

from ranger_ai_agent.config import RangerConfig
from ranger_ai_agent.identity import (
    AUTH_RANGER,
    AUTH_UNVERIFIED,
    PROFILE_PATH,
    ReviewerAuthError,
    check_reviewer,
    reviewer_from_env,
)

CONFIG = RangerConfig(base_url="https://ranger.example:6182/", username="ranger_ai_agent", verify_tls="/etc/ca.pem", timeout_seconds=7)
ADMIN = {"loginId": "alice", "userRoleList": ["ROLE_SYS_ADMIN"]}


class FakeResponse:
    def __init__(self, status, body=None, raw=None):
        self.status_code = status
        self._body = body
        self._raw = raw

    def json(self):
        if self._raw is not None:
            raise ValueError("not json")
        return self._body


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        return self.response


def test_confirmed_admin_is_recorded_with_ranger_login():
    session = FakeSession(FakeResponse(200, dict(ADMIN, loginId="Alice")))
    reviewer = check_reviewer(CONFIG, " alice ", "pw", session)
    assert reviewer.login == "Alice" and reviewer.auth == AUTH_RANGER
    url, kwargs = session.calls[0]
    assert url == "https://ranger.example:6182" + PROFILE_PATH
    assert kwargs["auth"] == ("alice", "pw")  # the reviewer's credentials, never the agent's
    assert kwargs["allow_redirects"] is False
    assert kwargs["verify"] == "/etc/ca.pem" and kwargs["timeout"] == 7


@pytest.mark.parametrize(
    "response, message",
    [
        (FakeResponse(401), "did not accept"),
        (FakeResponse(403), "did not accept"),
        (FakeResponse(302), "HTTP 302"),
        (FakeResponse(200, raw="<html>login</html>"), "no user profile"),
        (FakeResponse(200, None), "no user profile"),
        (FakeResponse(200, {"loginId": "mallory", "userRoleList": ["ROLE_SYS_ADMIN"]}), "different user"),
        (FakeResponse(200, {"loginId": "alice", "userRoleList": ["ROLE_USER"]}), "not a Ranger system administrator"),
        (FakeResponse(200, {"loginId": "alice", "userRoleList": ["ROLE_ADMIN_AUDITOR"]}), "not a Ranger system administrator"),
        (FakeResponse(200, {"loginId": "alice", "userRoleList": "ROLE_SYS_ADMIN"}), "not a Ranger system administrator"),
    ],
)
def test_unconfirmed_reviewers_are_refused(response, message):
    with pytest.raises(ReviewerAuthError, match=message):
        check_reviewer(CONFIG, "alice", "pw", FakeSession(response))


def test_agent_service_account_cannot_review():
    session = FakeSession(FakeResponse(200, {"loginId": "ranger_ai_agent", "userRoleList": ["ROLE_SYS_ADMIN"]}))
    with pytest.raises(ReviewerAuthError, match="service account"):
        check_reviewer(CONFIG, "RANGER_AI_AGENT", "pw", session)
    assert session.calls == []  # refused before any credentials are sent


def test_missing_password_and_unreachable_ranger_are_refused():
    with pytest.raises(ReviewerAuthError, match="password"):
        check_reviewer(CONFIG, "alice", "", FakeSession(FakeResponse(200, ADMIN)))
    with pytest.raises(ReviewerAuthError, match="could not reach"):
        check_reviewer(CONFIG, "alice", "pw", FakeSession(error=requests.ConnectionError("refused")))


def test_env_password_prompt_and_modes(monkeypatch):
    for name in ("RANGER_AI_REVIEWER_AUTH", "RANGER_AI_REVIEWER_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    seen = []
    monkeypatch.setattr("ranger_ai_agent.identity.check_reviewer", lambda config, login, password: seen.append(password) or "ok")

    with pytest.raises(ReviewerAuthError, match="RANGER_AI_REVIEWER_PASSWORD"):
        reviewer_from_env(CONFIG, "alice", interactive=False)
    assert reviewer_from_env(CONFIG, "alice", prompt=lambda text: "typed", interactive=True) == "ok"
    monkeypatch.setenv("RANGER_AI_REVIEWER_PASSWORD", "from-env")
    reviewer_from_env(CONFIG, "alice", interactive=False)
    assert seen == ["typed", "from-env"]

    monkeypatch.setenv("RANGER_AI_REVIEWER_AUTH", "none")
    reviewer = reviewer_from_env(CONFIG, " bob ")
    assert (reviewer.login, reviewer.auth) == ("bob", AUTH_UNVERIFIED)
    monkeypatch.setenv("RANGER_AI_REVIEWER_AUTH", "ldap")
    with pytest.raises(ValueError, match="'ranger' or 'none'"):
        reviewer_from_env(CONFIG, "alice")
