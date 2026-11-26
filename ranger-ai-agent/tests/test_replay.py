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

from ranger_ai_agent.clients.ranger_admin import RangerAdminReader
from ranger_ai_agent.clients.solr_audit import SolrAuditReader
from ranger_ai_agent.detectors import Finding
from ranger_ai_agent.features.snapshot import SnapshotBuilder
from ranger_ai_agent.replay import Metrics, evaluate, first_flagged, replay
from ranger_ai_agent.synthetic import build_scenario


def test_all_planted_anomalies_found_with_no_false_positives_at_as_of():
    sc = build_scenario()
    results = replay(SnapshotBuilder(sc.source, sc.source), [sc.as_of])
    metrics = evaluate(results[0].findings, sc.expected)
    assert metrics == Metrics(true_positives=3, false_positives=0, false_negatives=0)
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0


def test_anomalies_appear_only_once_visible_in_history():
    sc = build_scenario()
    builder = SnapshotBuilder(sc.source, sc.source)
    early, late = replay(builder, [sc.as_of - timedelta(days=10), sc.as_of])

    early_keys = {f.key for f in early.findings}
    late_keys = {f.key for f in late.findings}
    assert ("ABNORMAL_ACCESS_TIME", None, "dave") not in early_keys
    assert ("ABNORMAL_ACCESS_TIME", None, "dave") in late_keys
    # the stale policy is old enough to be flagged well before the scenario end
    assert ("STALE_POLICY", 9, None) in early_keys


def test_first_flagged_reports_earliest_appearance():
    sc = build_scenario()
    builder = SnapshotBuilder(sc.source, sc.source)
    results = replay(builder, [sc.as_of - timedelta(days=10), sc.as_of])
    first = first_flagged(results)
    assert first[("STALE_POLICY", 9, None)] == sc.as_of - timedelta(days=10)
    assert first[("ABNORMAL_ACCESS_TIME", None, "dave")] == sc.as_of


def test_evaluate_counts_true_false_and_missed():
    findings = [
        Finding(kind="K", confidence=1.0, summary="", policy_id=1, user="a"),
        Finding(kind="K", confidence=1.0, summary="", policy_id=2, user="b"),
    ]
    expected = [("K", 1, "a"), ("K", 3, "c")]
    metrics = evaluate(findings, expected)
    assert (metrics.true_positives, metrics.false_positives, metrics.false_negatives) == (1, 1, 1)
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5


def test_metrics_are_defined_with_no_predictions_or_no_expectations():
    assert evaluate([], []).precision == 1.0
    assert evaluate([], []).recall == 1.0
    assert evaluate([], [("K", 1, "a")]).recall == 0.0


def test_live_clients_expose_the_methods_the_builder_uses():
    for name in ("policy_usage", "user_usage_for_policy", "hourly_histogram", "active_users"):
        assert callable(getattr(SolrAuditReader, name))
    assert callable(getattr(RangerAdminReader, "list_policies"))
