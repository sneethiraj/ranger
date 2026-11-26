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

from ranger_ai_agent.clients.ranger_admin import RangerAdminReader, RangerApiError
from ranger_ai_agent.config import RangerConfig


class FakeResponse:
    def __init__(self, status=200, body=None, json_error=False):
        self.status_code = status
        self._body = body
        self._json_error = json_error

    def json(self):
        if self._json_error:
            raise ValueError("not json")
        return self._body


class FakeSession:
    """Records calls and replays queued responses; any non-GET use fails."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}
        self.auth = None
        self.verify = None

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, dict(params or {})))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def post(self, *args, **kwargs):
        raise AssertionError("read-only client must not POST")

    put = delete = patch = post


def make_reader(responses, page_size=2):
    cfg = RangerConfig(base_url="http://ranger:6080/", username="u", password="p", page_size=page_size)
    session = FakeSession(responses)
    return RangerAdminReader(cfg, session), session


def test_policies_paginate_until_short_page():
    reader, session = make_reader(
        [
            FakeResponse(body=[{"id": 1}, {"id": 2}]),
            FakeResponse(body=[{"id": 3}]),
        ]
    )
    policies = reader.list_policies()
    assert [p["id"] for p in policies] == [1, 2, 3]
    assert session.calls[0][0] == "http://ranger:6080/service/public/v2/api/policy"
    assert session.calls[0][1] == {"pageSize": 2, "startIndex": 0}
    assert session.calls[1][1] == {"pageSize": 2, "startIndex": 2}


def test_policies_filter_by_service():
    reader, session = make_reader([FakeResponse(body=[])])
    reader.list_policies(service_name="hive_dev")
    assert session.calls[0][1]["serviceName"] == "hive_dev"


def test_credentials_and_tls_applied_to_session():
    reader, session = make_reader([])
    assert session.auth == ("u", "p")
    assert session.verify is True


def test_http_error_raises():
    reader, _ = make_reader([FakeResponse(status=403)])
    with pytest.raises(RangerApiError, match="HTTP 403"):
        reader.list_services()


def test_network_error_wrapped():
    reader, _ = make_reader([requests.ConnectionError("down")])
    with pytest.raises(RangerApiError, match="failed"):
        reader.list_roles()


def test_non_json_body_raises():
    reader, _ = make_reader([FakeResponse(json_error=True)])
    with pytest.raises(RangerApiError, match="non-JSON"):
        reader.get_policy(7)


def test_list_endpoint_must_return_list():
    reader, _ = make_reader([FakeResponse(body={"oops": 1})])
    with pytest.raises(RangerApiError, match="expected a JSON list"):
        reader.list_zones()


def test_users_unwrap_vxusers():
    reader, session = make_reader(
        [
            FakeResponse(body={"vXUsers": [{"name": "a"}, {"name": "b"}]}),
            FakeResponse(body={"vXUsers": [{"name": "c"}]}),
        ]
    )
    assert [u["name"] for u in reader.list_users()] == ["a", "b", "c"]
    assert session.calls[0][0].endswith("/service/xusers/users")


def test_client_never_writes():
    reader, session = make_reader([FakeResponse(body=[])])
    reader.list_services()
    assert all(call[0].startswith("http://") for call in session.calls)
