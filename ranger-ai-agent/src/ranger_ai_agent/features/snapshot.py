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

"""Point-in-time feature snapshots.

A snapshot captures everything the detectors need as of one instant: policy
metadata, per-policy and per-grant usage, and hour-of-day histograms for
recent and baseline windows. Snapshots are self-contained, so detectors can
be re-run later without querying the audit store again.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Sequence, Tuple

from ranger_ai_agent.models import PolicyRecord, UsageStat, ensure_utc, parse_policy
from ranger_ai_agent.sources import AuditSource, PolicySource

ONE_SECOND = timedelta(seconds=1)

FEATURE_POLICY = "policy"
FEATURE_POLICY_USAGE = "policy_usage"
FEATURE_GRANT_USAGE = "grant_usage"
FEATURE_RECENT_HOURS = "recent_hours"
FEATURE_BASELINE_HOURS = "baseline_hours"


def normalize_as_of(value: datetime) -> datetime:
    """Snapshots are keyed by whole-second UTC instants."""
    return ensure_utc(value).replace(microsecond=0)


@dataclass
class FeatureSnapshot:
    as_of: datetime
    lookback_days: int
    recent_days: int
    baseline_days: int
    policies: Dict[int, PolicyRecord] = field(default_factory=dict)
    policy_usage: Dict[int, UsageStat] = field(default_factory=dict)
    # (policy_id, user) -> allowed usage over the lookback window.
    # A missing key means the user had no allowed events through that policy.
    grant_usage: Dict[Tuple[int, str], UsageStat] = field(default_factory=dict)
    recent_hours: Dict[str, List[int]] = field(default_factory=dict)
    baseline_hours: Dict[str, List[int]] = field(default_factory=dict)

    def to_feature_rows(self) -> List[Tuple[str, str, str]]:
        """Flatten into (feature_type, entity_key, json_payload) rows for storage."""
        rows: List[Tuple[str, str, str]] = []
        for pid, policy in self.policies.items():
            rows.append((FEATURE_POLICY, str(pid), json.dumps(policy.to_dict(), sort_keys=True)))
        for pid, usage in self.policy_usage.items():
            rows.append((FEATURE_POLICY_USAGE, str(pid), json.dumps(usage.to_dict(), sort_keys=True)))
        for (pid, user), usage in self.grant_usage.items():
            rows.append((FEATURE_GRANT_USAGE, "%d|%s" % (pid, user), json.dumps(usage.to_dict(), sort_keys=True)))
        for user, hours in self.recent_hours.items():
            rows.append((FEATURE_RECENT_HOURS, user, json.dumps(hours)))
        for user, hours in self.baseline_hours.items():
            rows.append((FEATURE_BASELINE_HOURS, user, json.dumps(hours)))
        return rows

    @classmethod
    def from_feature_rows(
        cls,
        as_of: datetime,
        lookback_days: int,
        recent_days: int,
        baseline_days: int,
        rows: Sequence[Tuple[str, str, str]],
    ) -> "FeatureSnapshot":
        snap = cls(as_of=normalize_as_of(as_of), lookback_days=lookback_days, recent_days=recent_days, baseline_days=baseline_days)
        for feature_type, key, payload in rows:
            value = json.loads(payload)
            if feature_type == FEATURE_POLICY:
                snap.policies[int(key)] = PolicyRecord.from_dict(value)
            elif feature_type == FEATURE_POLICY_USAGE:
                snap.policy_usage[int(key)] = UsageStat.from_dict(value)
            elif feature_type == FEATURE_GRANT_USAGE:
                pid, user = key.split("|", 1)
                snap.grant_usage[(int(pid), user)] = UsageStat.from_dict(value)
            elif feature_type == FEATURE_RECENT_HOURS:
                snap.recent_hours[key] = [int(v) for v in value]
            elif feature_type == FEATURE_BASELINE_HOURS:
                snap.baseline_hours[key] = [int(v) for v in value]
            else:
                raise ValueError("unknown feature type: %r" % (feature_type,))
        return snap


class SnapshotBuilder:
    """Builds FeatureSnapshots from an audit source and a policy source.

    Windows, for an as-of instant T:
      usage (grants and policies): [T - lookback_days, T]
      recent hour histogram:       [T - recent_days, T]
      baseline hour histogram:     [T - recent_days - baseline_days, T - recent_days - 1s]
    """

    def __init__(
        self,
        audit: AuditSource,
        policies: PolicySource,
        lookback_days: int = 90,
        recent_days: int = 7,
        baseline_days: int = 30,
    ) -> None:
        if min(lookback_days, recent_days, baseline_days) <= 0:
            raise ValueError("all windows must be at least one day")
        self._audit = audit
        self._policies = policies
        self.lookback_days = lookback_days
        self.recent_days = recent_days
        self.baseline_days = baseline_days

    def build(self, as_of: datetime) -> FeatureSnapshot:
        as_of = normalize_as_of(as_of)
        lookback_start = as_of - timedelta(days=self.lookback_days)
        recent_start = as_of - timedelta(days=self.recent_days)
        baseline_start = recent_start - timedelta(days=self.baseline_days)
        baseline_end = recent_start - ONE_SECOND

        snap = FeatureSnapshot(
            as_of=as_of,
            lookback_days=self.lookback_days,
            recent_days=self.recent_days,
            baseline_days=self.baseline_days,
        )

        for raw in self._policies.list_policies():
            policy = parse_policy(raw)
            snap.policies[policy.policy_id] = policy

        for usage in self._audit.policy_usage(lookback_start, as_of):
            snap.policy_usage[usage.policy_id] = UsageStat(usage.allowed_count, usage.last_allowed)

        for pid, policy in snap.policies.items():
            if not policy.enabled or not policy.allow_users:
                continue
            granted = set(policy.allow_users)
            for usage in self._audit.user_usage_for_policy(pid, lookback_start, as_of):
                if usage.user in granted:
                    snap.grant_usage[(pid, usage.user)] = UsageStat(usage.allowed_count, usage.last_allowed)

        for user in self._audit.active_users(recent_start, as_of):
            snap.recent_hours[user] = self._audit.hourly_histogram(user, recent_start, as_of)
            snap.baseline_hours[user] = self._audit.hourly_histogram(user, baseline_start, baseline_end)

        return snap
