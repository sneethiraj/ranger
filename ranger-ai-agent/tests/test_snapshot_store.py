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

from datetime import timedelta

from ranger_ai_agent.features.snapshot import SnapshotBuilder
from ranger_ai_agent.features.store import FeatureStore
from ranger_ai_agent.replay import as_of_series, replay
from ranger_ai_agent.synthetic import build_scenario


class CountingSource:
    """Wraps a source and counts calls, so tests can prove the store served a replay."""

    def __init__(self, inner):
        self._inner = inner
        self.calls = 0

    def __getattr__(self, name):
        attr = getattr(self._inner, name)
        if not callable(attr):
            return attr

        def counted(*args, **kwargs):
            self.calls += 1
            return attr(*args, **kwargs)

        return counted


def test_snapshot_contains_only_events_up_to_as_of():
    sc = build_scenario()
    as_of = sc.as_of - timedelta(days=10)
    snap = SnapshotBuilder(sc.source, sc.source).build(as_of)

    recent_start = as_of - timedelta(days=7)
    expected = sum(1 for e in sc.source.events if e.user == "dave" and recent_start <= e.when <= as_of)
    assert sum(snap.recent_hours["dave"]) == expected
    # dave's night work starts 7 days before the scenario end, so it must not be visible yet
    assert snap.recent_hours["dave"][22] == 0


def test_store_round_trip_is_lossless():
    sc = build_scenario()
    snap = SnapshotBuilder(sc.source, sc.source).build(sc.as_of)
    with FeatureStore() as store:
        store.save(snap)
        loaded = store.load(sc.as_of, snap.lookback_days, snap.recent_days, snap.baseline_days)
    assert loaded == snap


def test_saving_same_snapshot_twice_is_idempotent():
    sc = build_scenario()
    snap = SnapshotBuilder(sc.source, sc.source).build(sc.as_of)
    with FeatureStore() as store:
        first_id = store.save(snap)
        second_id = store.save(snap)
        assert first_id == second_id
        assert store.snapshot_count() == 1
        assert store.load(sc.as_of, snap.lookback_days, snap.recent_days, snap.baseline_days) == snap


def test_store_misses_when_window_parameters_differ():
    sc = build_scenario()
    snap = SnapshotBuilder(sc.source, sc.source).build(sc.as_of)
    with FeatureStore() as store:
        store.save(snap)
        assert store.load(sc.as_of, 60, snap.recent_days, snap.baseline_days) is None
        assert store.load(sc.as_of - timedelta(days=1), snap.lookback_days, snap.recent_days, snap.baseline_days) is None


def test_replay_reuses_stored_snapshots_without_querying_audit():
    sc = build_scenario()
    counting = CountingSource(sc.source)
    builder = SnapshotBuilder(counting, counting)
    as_ofs = as_of_series(sc.as_of - timedelta(days=5), sc.as_of)

    with FeatureStore() as store:
        first = replay(builder, as_ofs, store=store)
        assert counting.calls > 0

        counting.calls = 0
        second = replay(builder, as_ofs, store=store)
        assert counting.calls == 0
        assert [r.findings for r in second] == [r.findings for r in first]
        assert store.snapshot_count() == len(as_ofs)


def test_as_of_series_is_inclusive_and_validates_step():
    series = as_of_series(build_scenario().as_of - timedelta(days=30), build_scenario().as_of, 1)
    assert len(series) == 31
    assert series[0] < series[-1]
    try:
        as_of_series(series[0], series[-1], 0)
    except ValueError:
        pass
    else:
        raise AssertionError("step_days=0 should be rejected")
