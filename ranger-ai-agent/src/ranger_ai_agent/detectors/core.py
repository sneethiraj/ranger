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

"""Finding and detector configuration types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Optional, Tuple

DEFAULT_OFF_HOURS_UTC: FrozenSet[int] = frozenset(range(18, 24)) | frozenset(range(0, 6))


@dataclass(frozen=True)
class Finding:
    """One detector output. `confidence` is the detector's own score in [0, 1]."""

    kind: str
    confidence: float
    summary: str
    policy_id: Optional[int] = None
    user: Optional[str] = None
    evidence: Tuple[str, ...] = ()

    @property
    def key(self) -> Tuple[str, Optional[int], Optional[str]]:
        """Identity used for evaluation: (kind, policy_id, user)."""
        return (self.kind, self.policy_id, self.user)


@dataclass(frozen=True)
class DetectorConfig:
    # Over-privileged: the policy must show at least this many allowed events in the lookback.
    min_policy_events: int = 20
    # Stale: policy must have been created or changed at least this many days before as_of.
    stale_days: int = 90
    stale_confidence: float = 0.8
    # Abnormal access time: hours (UTC) treated as off-hours.
    off_hours_utc: FrozenSet[int] = DEFAULT_OFF_HOURS_UTC
    min_recent_events: int = 10
    min_baseline_events: int = 30
    z_threshold: float = 3.0
    min_share_delta: float = 0.2
    # Service and automation accounts that should never be flagged.
    exclude_users: FrozenSet[str] = frozenset()
