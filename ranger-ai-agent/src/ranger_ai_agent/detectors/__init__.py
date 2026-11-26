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

"""Detector entry point: runs all rules over one feature snapshot."""

from __future__ import annotations

from typing import List, Optional

from ranger_ai_agent.detectors.core import DetectorConfig, Finding
from ranger_ai_agent.detectors.rules import (
    KIND_ABNORMAL_ACCESS_TIME,
    KIND_OVER_PRIVILEGED,
    KIND_STALE_POLICY,
    detect_abnormal_access_time,
    detect_over_privileged,
    detect_stale_policies,
)
from ranger_ai_agent.features.snapshot import FeatureSnapshot

__all__ = [
    "DetectorConfig",
    "Finding",
    "KIND_ABNORMAL_ACCESS_TIME",
    "KIND_OVER_PRIVILEGED",
    "KIND_STALE_POLICY",
    "run_detectors",
]


def run_detectors(snap: FeatureSnapshot, cfg: Optional[DetectorConfig] = None) -> List[Finding]:
    cfg = cfg or DetectorConfig()

    if cfg.stale_days > snap.lookback_days:
        raise ValueError(
            "stale_days (%d) must not exceed the snapshot lookback (%d days); "
            "otherwise a policy can be called stale while it was used just outside the window"
            % (cfg.stale_days, snap.lookback_days)
        )
    if any(h < 0 or h > 23 for h in cfg.off_hours_utc):
        raise ValueError("off_hours_utc must contain hours 0..23")

    findings = (
        detect_over_privileged(snap, cfg)
        + detect_stale_policies(snap, cfg)
        + detect_abnormal_access_time(snap, cfg)
    )
    return sorted(findings, key=lambda f: (f.kind, -1 if f.policy_id is None else f.policy_id, f.user or ""))
