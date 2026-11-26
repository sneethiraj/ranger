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

from ranger_ai_agent.detectors import DetectorConfig, run_detectors
from ranger_ai_agent.detectors.rules import (
    KIND_ABNORMAL_ACCESS_TIME,
    KIND_OVER_PRIVILEGED,
    KIND_STALE_POLICY,
    detect_abnormal_access_time,
    detect_over_privileged,
    detect_stale_policies,
)
from ranger_ai_agent.features.snapshot import SnapshotBuilder
from ranger_ai_agent.synthetic import build_scenario


@pytest.fixture(scope="module")
def snap():
    sc = build_scenario()
    return SnapshotBuilder(sc.source, sc.source).build(sc.as_of)


def test_over_privileged_flags_only_the_unused_grant(snap):
    findings = detect_over_privileged(snap, DetectorConfig())
    assert [(f.policy_id, f.user) for f in findings] == [(1, "carol")]
    assert findings[0].kind == KIND_OVER_PRIVILEGED
    assert findings[0].confidence == pytest.approx(0.9)


def test_stale_flags_only_the_old_unused_policy(snap):
    findings = detect_stale_policies(snap, DetectorConfig())
    # policy 10 is unused but only 5 days old, so it must not be flagged
    assert [(f.policy_id, f.user) for f in findings] == [(9, None)]
    assert findings[0].kind == KIND_STALE_POLICY


def test_abnormal_time_flags_only_the_user_who_changed_hours(snap):
    findings = detect_abnormal_access_time(snap, DetectorConfig())
    assert [f.user for f in findings] == ["dave"]
    assert findings[0].kind == KIND_ABNORMAL_ACCESS_TIME
    assert findings[0].confidence == pytest.approx(0.95)


def test_night_shift_user_is_not_flagged(snap):
    # nightops is always at night, so the same off-hours share is their normal pattern
    findings = detect_abnormal_access_time(snap, DetectorConfig())
    assert "nightops" not in {f.user for f in findings}


def test_combined_run_is_deterministic(snap):
    assert run_detectors(snap) == run_detectors(snap)


def test_exclude_users_suppresses_findings(snap):
    cfg = DetectorConfig(exclude_users=frozenset({"carol", "dave"}))
    assert not any(f.user in {"carol", "dave"} for f in run_detectors(snap, cfg))


def test_min_policy_events_gates_over_privileged(snap):
    assert detect_over_privileged(snap, DetectorConfig(min_policy_events=10**9)) == []


def test_z_threshold_gates_abnormal_time(snap):
    assert detect_abnormal_access_time(snap, DetectorConfig(z_threshold=1e6)) == []


def test_min_share_delta_gates_abnormal_time(snap):
    assert detect_abnormal_access_time(snap, DetectorConfig(min_share_delta=1.01)) == []


def test_stale_window_cannot_exceed_lookback(snap):
    with pytest.raises(ValueError, match="must not exceed"):
        run_detectors(snap, DetectorConfig(stale_days=snap.lookback_days + 1))


def test_off_hours_must_be_valid_hours(snap):
    with pytest.raises(ValueError, match="0..23"):
        run_detectors(snap, DetectorConfig(off_hours_utc=frozenset({24})))
