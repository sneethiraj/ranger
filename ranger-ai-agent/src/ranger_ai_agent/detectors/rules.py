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

"""Deterministic detectors. No LLM is involved in deciding what is anomalous.

Confidence formulas are heuristics and are documented in README.md.
"""

from __future__ import annotations

import math
from typing import List

from ranger_ai_agent.detectors.core import DetectorConfig, Finding
from ranger_ai_agent.features.snapshot import FeatureSnapshot

KIND_OVER_PRIVILEGED = "OVER_PRIVILEGED"
KIND_STALE_POLICY = "STALE_POLICY"
KIND_ABNORMAL_ACCESS_TIME = "ABNORMAL_ACCESS_TIME"


def detect_over_privileged(snap: FeatureSnapshot, cfg: DetectorConfig) -> List[Finding]:
    """A user is granted a policy that is active, yet the user never used it in the lookback."""
    findings: List[Finding] = []
    window = snap.lookback_days

    for pid in sorted(snap.policies):
        policy = snap.policies[pid]
        if not policy.enabled or not policy.allow_users:
            continue

        usage = snap.policy_usage.get(pid)
        policy_events = usage.count if usage is not None else 0
        if policy_events < cfg.min_policy_events:
            continue

        for user in policy.allow_users:
            if user in cfg.exclude_users:
                continue
            grant = snap.grant_usage.get((pid, user))
            if grant is not None and grant.count > 0:
                continue

            findings.append(
                Finding(
                    kind=KIND_OVER_PRIVILEGED,
                    confidence=round(0.6 + 0.3 * min(1.0, policy_events / 50.0), 3),
                    policy_id=pid,
                    user=user,
                    summary=(
                        "User '%s' is granted policy %d ('%s') but had no allowed access through it "
                        "in the last %d days, while the policy served %d allowed events from other users."
                        % (user, pid, policy.name, window, policy_events)
                    ),
                    evidence=(
                        "policy:%d" % pid,
                        "policy allowed events in %dd: %d" % (window, policy_events),
                        "allowed events by %s through this policy in %dd: 0" % (user, window),
                    ),
                )
            )
    return findings


def detect_stale_policies(snap: FeatureSnapshot, cfg: DetectorConfig) -> List[Finding]:
    """An enabled policy, unchanged for a long time, with no allowed matches in the lookback."""
    findings: List[Finding] = []
    window = snap.lookback_days

    for pid in sorted(snap.policies):
        policy = snap.policies[pid]
        if not policy.enabled:
            continue

        last_changed = policy.last_changed()
        if last_changed is None:
            continue
        age_days = (snap.as_of - last_changed).days
        if age_days < cfg.stale_days:
            continue

        usage = snap.policy_usage.get(pid)
        if usage is not None and usage.count > 0:
            continue

        findings.append(
            Finding(
                kind=KIND_STALE_POLICY,
                confidence=cfg.stale_confidence,
                policy_id=pid,
                user=None,
                summary=(
                    "Policy %d ('%s') had no allowed access in the last %d days and was last changed %d days ago."
                    % (pid, policy.name, window, age_days)
                ),
                evidence=(
                    "policy:%d" % pid,
                    "last changed: %s" % (last_changed.strftime("%Y-%m-%dT%H:%M:%SZ")),
                    "allowed events in %dd: 0" % window,
                ),
            )
        )
    return findings


def detect_abnormal_access_time(snap: FeatureSnapshot, cfg: DetectorConfig) -> List[Finding]:
    """A user's recent share of off-hours events is far above their own baseline.

    The baseline share is Laplace-smoothed so that a user with no off-hours
    history still gets a finite standard error. The test is a one-sample
    binomial z-score of the recent proportion against the baseline proportion.
    """
    findings: List[Finding] = []
    off_hours = cfg.off_hours_utc

    for user in sorted(snap.recent_hours):
        if user in cfg.exclude_users:
            continue

        recent = snap.recent_hours[user]
        baseline = snap.baseline_hours.get(user, [0] * 24)
        n_recent = sum(recent)
        n_baseline = sum(baseline)
        if n_recent < cfg.min_recent_events or n_baseline < cfg.min_baseline_events:
            continue

        share_recent = sum(recent[h] for h in off_hours) / float(n_recent)
        share_baseline = (sum(baseline[h] for h in off_hours) + 1.0) / (n_baseline + 2.0)
        standard_error = math.sqrt(share_baseline * (1.0 - share_baseline) / n_recent)
        z = (share_recent - share_baseline) / standard_error

        if z < cfg.z_threshold or (share_recent - share_baseline) < cfg.min_share_delta:
            continue

        findings.append(
            Finding(
                kind=KIND_ABNORMAL_ACCESS_TIME,
                confidence=round(min(0.95, 0.5 + 0.1 * z), 3),
                policy_id=None,
                user=user,
                summary=(
                    "User '%s' generated %.0f%% of %d recent events outside the configured hours (UTC), "
                    "versus %.1f%% over a baseline of %d events (z=%.1f)."
                    % (user, share_recent * 100, n_recent, share_baseline * 100, n_baseline, z)
                ),
                evidence=(
                    "recent window: %dd, %d events" % (snap.recent_days, n_recent),
                    "baseline window: %dd, %d events" % (snap.baseline_days, n_baseline),
                    "off-hours share recent=%.3f baseline=%.3f" % (share_recent, share_baseline),
                ),
            )
        )
    return findings
