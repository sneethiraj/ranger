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

"""Synthetic audit history with planted anomalies and ground truth.

The scenario has 120 days of normal activity and three planted anomalies,
plus false-positive controls that look unusual but are legitimate:

  * over-privileged: carol is granted policy 1 and never uses it
  * abnormal time:   dave works business hours, then starts working at night
                     in the final 7 days
  * stale policy:    policy 9 was last changed 400 days ago and is unused
  * control:         nightops always works at night, so night work is normal for them
  * control:         policy 10 is new and unused, which is not yet stale

The in-memory source implements the same AuditSource and PolicySource
protocols as the live clients, so the real snapshot and detector code runs
unchanged.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from ranger_ai_agent.clients.solr_audit import PolicyUsage, UserPolicyUsage
from ranger_ai_agent.detectors.rules import KIND_ABNORMAL_ACCESS_TIME, KIND_OVER_PRIVILEGED, KIND_STALE_POLICY
from ranger_ai_agent.models import UTC, format_utc

DEFAULT_AS_OF = datetime(2026, 6, 1, tzinfo=UTC)
BUSINESS_HOURS = tuple(range(9, 17))
NIGHT_SHIFT_HOURS = (22, 23)
DAVE_NIGHT_HOURS = (22, 23, 0, 1, 2)

ExpectedKey = Tuple[str, Optional[int], Optional[str]]


@dataclass(frozen=True)
class AuditEvent:
    when: datetime
    user: str
    policy_id: int


class SyntheticRanger:
    """In-memory stand-in for the Solr audit collection and Ranger policy JSON."""

    def __init__(self, events: List[AuditEvent], policies_raw: List[Dict[str, Any]]) -> None:
        self._events = sorted(events, key=lambda e: e.when)
        self._policies = policies_raw

    @property
    def events(self) -> List[AuditEvent]:
        return list(self._events)

    def list_policies(self, service_name: Optional[str] = None) -> List[Dict[str, Any]]:
        return [dict(p) for p in self._policies]

    def _window(self, start: datetime, end: datetime) -> List[AuditEvent]:
        return [e for e in self._events if start <= e.when <= end]

    def policy_usage(self, start: datetime, end: datetime) -> List[PolicyUsage]:
        agg: Dict[int, Tuple[int, datetime]] = {}
        for event in self._window(start, end):
            if event.policy_id <= 0:
                continue
            count, last = agg.get(event.policy_id, (0, event.when))
            agg[event.policy_id] = (count + 1, max(last, event.when))
        return [
            PolicyUsage(policy_id=pid, allowed_count=count, last_allowed=format_utc(last))
            for pid, (count, last) in sorted(agg.items())
        ]

    def user_usage_for_policy(self, policy_id: int, start: datetime, end: datetime) -> List[UserPolicyUsage]:
        agg: Dict[str, Tuple[int, datetime]] = {}
        for event in self._window(start, end):
            if event.policy_id != policy_id:
                continue
            count, last = agg.get(event.user, (0, event.when))
            agg[event.user] = (count + 1, max(last, event.when))
        return [
            UserPolicyUsage(user=user, allowed_count=count, last_allowed=format_utc(last))
            for user, (count, last) in sorted(agg.items())
        ]

    def hourly_histogram(self, user: str, start: datetime, end: datetime) -> List[int]:
        histogram = [0] * 24
        for event in self._window(start, end):
            if event.user == user:
                histogram[event.when.hour] += 1
        return histogram

    def active_users(self, start: datetime, end: datetime) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for event in self._window(start, end):
            counts[event.user] = counts.get(event.user, 0) + 1
        return counts


@dataclass(frozen=True)
class Scenario:
    as_of: datetime
    source: SyntheticRanger
    expected: Set[ExpectedKey]


def _ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def _raw_policy(
    policy_id: int,
    name: str,
    users: List[str],
    created: datetime,
    updated: datetime,
    enabled: bool = True,
) -> Dict[str, Any]:
    """Policy JSON in the shape returned by Ranger's public API v2."""
    return {
        "id": policy_id,
        "name": name,
        "service": "hive_prod",
        "isEnabled": enabled,
        "createTime": _ms(created),
        "updateTime": _ms(updated),
        "policyItems": [
            {
                "users": list(users),
                "groups": [],
                "accesses": [{"type": "select", "isAllowed": True}],
                "delegateAdmin": False,
            }
        ],
        "denyPolicyItems": [],
        "allowExceptions": [],
        "denyExceptions": [],
    }


def build_scenario(seed: int = 7, as_of: datetime = DEFAULT_AS_OF, history_days: int = 120) -> Scenario:
    rng = random.Random(seed)
    events: List[AuditEvent] = []

    def emit(offset_days: int, hours: Tuple[int, ...], count: int, user: str, policy_id: int) -> None:
        day = as_of + timedelta(days=offset_days)
        for _ in range(count):
            when = day.replace(hour=rng.choice(hours), minute=rng.randrange(60), second=rng.randrange(60))
            events.append(AuditEvent(when=when, user=user, policy_id=policy_id))

    for offset in range(-history_days, 0):
        emit(offset, BUSINESS_HOURS, rng.randint(3, 6), "alice", 1)
        if rng.random() < 0.6:
            emit(offset, BUSINESS_HOURS, rng.randint(2, 4), "bob", rng.choice((1, 2)))
        emit(offset, NIGHT_SHIFT_HOURS, rng.randint(2, 3), "nightops", 3)
        emit(offset, BUSINESS_HOURS, rng.randint(2, 4), "dave", 1)
        if offset >= -7:
            emit(offset, DAVE_NIGHT_HOURS, rng.randint(2, 3), "dave", 1)

    policies = [
        _raw_policy(1, "hive_sales_read", ["alice", "bob", "dave", "carol"], as_of - timedelta(days=300), as_of - timedelta(days=200)),
        _raw_policy(2, "hive_bob_reports", ["bob"], as_of - timedelta(days=200), as_of - timedelta(days=100)),
        _raw_policy(3, "hive_night_ops", ["nightops"], as_of - timedelta(days=150), as_of - timedelta(days=150)),
        _raw_policy(9, "hive_legacy_archive", ["erin"], as_of - timedelta(days=400), as_of - timedelta(days=400)),
        _raw_policy(10, "hive_new_pilot", ["frank"], as_of - timedelta(days=5), as_of - timedelta(days=5)),
    ]

    expected: Set[ExpectedKey] = {
        (KIND_OVER_PRIVILEGED, 1, "carol"),
        (KIND_ABNORMAL_ACCESS_TIME, None, "dave"),
        (KIND_STALE_POLICY, 9, None),
    }
    return Scenario(as_of=as_of, source=SyntheticRanger(events, policies), expected=expected)
