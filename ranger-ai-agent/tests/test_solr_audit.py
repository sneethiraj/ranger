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
from datetime import datetime, timedelta, timezone

import pytest

from ranger_ai_agent.clients.solr_audit import (
    SolrAuditError,
    SolrAuditReader,
    quote_term,
    to_solr_date,
)
from ranger_ai_agent.config import SolrConfig

START = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = START + timedelta(days=2)


class FakeResponse:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.posts = []
        self.auth = None
        self.verify = None

    def post(self, url, data=None, timeout=None):
        self.posts.append((url, data))
        return self.response

    def get(self, *args, **kwargs):
        raise AssertionError("unexpected GET")


def make_reader(body, status=200):
    session = FakeSession(FakeResponse(status, body))
    return SolrAuditReader(SolrConfig(base_url="http://solr:6083/solr/"), session), session


def test_quote_term_escapes_injection():
    assert quote_term('bob" OR reqUser:*') == '"bob\\" OR reqUser:*"'
    assert quote_term("a\\b") == '"a\\\\b"'


def test_to_solr_date_converts_to_utc():
    assert to_solr_date(datetime(2026, 1, 1, 12, 0, tzinfo=timezone(timedelta(hours=-5)))) == "2026-01-01T17:00:00Z"
    assert to_solr_date(datetime(2026, 1, 1)) == "2026-01-01T00:00:00Z"


def test_count_uses_numfound_and_aggregate_only():
    reader, session = make_reader({"response": {"numFound": 42}})
    assert reader.count(START, END, "result:0") == 42
    url, body = session.posts[0]
    assert url == "http://solr:6083/solr/ranger_audits/select"
    assert body["rows"] == 0
    assert "result:0" in body["fq"]


def test_policy_usage_parses_buckets():
    reader, session = make_reader(
        {
            "facets": {
                "policies": {
                    "buckets": [
                        {"val": 11, "count": 5, "last": "2026-01-02T01:00:00Z"},
                        {"val": 12, "count": 1},
                    ]
                }
            }
        }
    )
    usage = reader.policy_usage(START, END)
    assert [(u.policy_id, u.allowed_count, u.last_allowed) for u in usage] == [
        (11, 5, "2026-01-02T01:00:00Z"),
        (12, 1, None),
    ]
    facet = json.loads(session.posts[0][1]["json.facet"])
    assert facet["policies"]["field"] == "policy"
    assert "result:1" in session.posts[0][1]["fq"]


def test_user_usage_for_policy_filters_on_policy_id():
    reader, session = make_reader(
        {"facets": {"users": {"buckets": [{"val": "alice", "count": 3, "last": "2026-01-02T00:00:00Z"}]}}}
    )
    usage = reader.user_usage_for_policy(7, START, END)
    assert usage[0].user == "alice" and usage[0].allowed_count == 3
    assert "policy:7" in session.posts[0][1]["fq"]


def test_user_usage_rejects_non_integer_policy_id():
    reader, _ = make_reader({})
    with pytest.raises(ValueError):
        reader.user_usage_for_policy("7 OR *:*", START, END)


def test_hourly_histogram_folds_into_hour_of_day():
    reader, session = make_reader(
        {
            "facets": {
                "by_hour": {
                    "buckets": [
                        {"val": "2026-01-01T09:00:00Z", "count": 4},
                        {"val": "2026-01-02T09:00:00Z", "count": 6},
                        {"val": "2026-01-02T23:00:00Z", "count": 1},
                    ]
                }
            }
        }
    )
    histogram = reader.hourly_histogram('eve" OR *:*', START, END)
    assert len(histogram) == 24
    assert histogram[9] == 10 and histogram[23] == 1 and sum(histogram) == 11
    # untrusted user name must arrive quoted
    assert any(fq.startswith('reqUser:"eve\\"') for fq in session.posts[0][1]["fq"])


def test_http_error_raises():
    reader, _ = make_reader({}, status=500)
    with pytest.raises(SolrAuditError, match="HTTP 500"):
        reader.count(START, END)


def test_active_users_maps_counts():
    reader, _ = make_reader({"facets": {"users": {"buckets": [{"val": "a", "count": 2}, {"val": "b", "count": 9}]}}})
    assert reader.active_users(START, END) == {"a": 2, "b": 9}
