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

from ranger_ai_agent.clients.ranger_admin import RangerApiError
from ranger_ai_agent.clients.ranger_admin_writer import RangerAdminWriter
from ranger_ai_agent.config import RangerConfig


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
        self.headers = {}
        self.verify = True
        self.auth = None

    def put(self, url, json=None, timeout=None):
        self.calls.append({"url": url, "json": json, "timeout": timeout})
        if self.error:
            raise self.error
        return self.response


def writer(session):
    return RangerAdminWriter(RangerConfig(base_url="https://ranger.example.com:6182/"), session=session)


def test_update_puts_full_policy_to_the_public_v2_path():
    session = FakeSession(FakeResponse(body={"id": 1, "version": 4}))
    body = {"id": 1, "name": "p", "policyItems": []}
    result = writer(session).update_policy(1, body)
    assert result == {"id": 1, "version": 4}
    call = session.calls[0]
    assert call["url"] == "https://ranger.example.com:6182/service/public/v2/api/policy/1"
    assert call["json"] == body
    assert call["timeout"] == 30.0


def test_body_id_must_match_the_target_policy():
    session = FakeSession(FakeResponse(body={}))
    with pytest.raises(ValueError, match="does not match"):
        writer(session).update_policy(1, {"id": 2})
    assert session.calls == []


def test_http_error_is_reported_without_response_body():
    session = FakeSession(FakeResponse(status=403, body={"msgDesc": "secret detail"}))
    with pytest.raises(RangerApiError, match="HTTP 403") as info:
        writer(session).update_policy(1, {"id": 1})
    assert "secret detail" not in str(info.value)


def test_transport_error_hides_exception_message():
    session = FakeSession(error=requests.ConnectionError("token=abc123"))
    with pytest.raises(RangerApiError, match="ConnectionError") as info:
        writer(session).update_policy(1, {"id": 1})
    assert "abc123" not in str(info.value)


def test_non_json_success_is_an_error():
    session = FakeSession(FakeResponse(not_json=True))
    with pytest.raises(RangerApiError, match="non-JSON"):
        writer(session).update_policy(1, {"id": 1})
