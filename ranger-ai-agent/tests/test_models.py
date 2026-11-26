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

from datetime import datetime

import pytest

from ranger_ai_agent.models import UTC, PolicyRecord, parse_policy, parse_ranger_time


def test_ranger_time_accepts_epoch_millis_and_iso_text():
    expected = datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)
    assert parse_ranger_time(1700000000000) == expected
    assert parse_ranger_time("1700000000000") == expected
    assert parse_ranger_time("2023-11-14T22:13:20Z") == expected
    assert parse_ranger_time("2023-11-14T22:13:20.999+00:00") == expected  # truncated to whole seconds


def test_ranger_time_none_and_bad_input():
    assert parse_ranger_time(None) is None
    assert parse_ranger_time("") is None
    with pytest.raises(ValueError):
        parse_ranger_time(True)


def test_parse_policy_uses_only_allowed_items():
    raw = {
        "id": 5,
        "name": "p",
        "service": "hive_prod",
        "isEnabled": True,
        "createTime": 1700000000000,
        "updateTime": None,
        "policyItems": [
            {"users": ["alice", "bob"], "groups": ["ops"], "accesses": [{"type": "select", "isAllowed": True}]},
            {"users": ["alice"], "groups": [], "accesses": [{"type": "drop", "isAllowed": False}]},
            {"users": ["mallory"], "groups": [], "accesses": []},
        ],
        "denyPolicyItems": [{"users": ["eve"], "accesses": [{"type": "select", "isAllowed": True}]}],
    }
    policy = parse_policy(raw)
    assert policy.policy_id == 5
    assert policy.allow_users == ("alice", "bob")
    assert policy.allow_groups == ("ops",)
    assert "eve" not in policy.allow_users
    assert policy.last_changed() == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)


def test_policy_record_round_trip():
    policy = PolicyRecord(
        policy_id=2,
        name="x",
        service="s",
        enabled=False,
        created=datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC),
        updated=None,
        allow_users=("a",),
        allow_groups=("g",),
    )
    assert PolicyRecord.from_dict(policy.to_dict()) == policy
