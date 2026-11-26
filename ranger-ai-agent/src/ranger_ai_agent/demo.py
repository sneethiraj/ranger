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

"""Runs the synthetic replay and prints a markdown report.

    PYTHONPATH=src python -m ranger_ai_agent.demo
"""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from typing import List, Sequence

from ranger_ai_agent.detectors import DetectorConfig
from ranger_ai_agent.features.snapshot import SnapshotBuilder
from ranger_ai_agent.features.store import FeatureStore
from ranger_ai_agent.replay import ReplayResult, as_of_series, evaluate, first_flagged, replay
from ranger_ai_agent.synthetic import Scenario, build_scenario


def _pct(value: float) -> str:
    return "%.2f" % value


def render_report(scenario: Scenario, results: Sequence[ReplayResult], replay_days: int) -> str:
    final = results[-1]
    lines: List[str] = []
    lines.append("# RANGER-5278 replay report (synthetic data)")
    lines.append("")
    lines.append(
        "As of `%s`; replayed %d snapshots from `%s` (1-day steps)."
        % (
            final.as_of.strftime("%Y-%m-%dT%H:%M:%SZ"),
            len(results),
            results[0].as_of.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
    )
    lines.append("")

    lines.append("## Findings at the final as-of instant")
    lines.append("")
    lines.append("| Kind | Policy | User | Confidence | Summary |")
    lines.append("|---|---|---|---|---|")
    for f in final.findings:
        lines.append(
            "| %s | %s | %s | %s | %s |"
            % (f.kind, "" if f.policy_id is None else f.policy_id, f.user or "", _pct(f.confidence), f.summary)
        )
    if not final.findings:
        lines.append("| _none_ | | | | |")
    lines.append("")

    lines.append("## Accuracy against planted anomalies")
    lines.append("")
    lines.append("| Scope | TP | FP | FN | Precision | Recall |")
    lines.append("|---|---|---|---|---|---|")
    kinds = sorted({key[0] for key in scenario.expected} | {f.kind for f in final.findings})
    for kind in kinds:
        m = evaluate(
            [f for f in final.findings if f.kind == kind],
            [key for key in scenario.expected if key[0] == kind],
        )
        lines.append("| %s | %d | %d | %d | %s | %s |" % (kind, m.true_positives, m.false_positives, m.false_negatives, _pct(m.precision), _pct(m.recall)))
    overall = evaluate(final.findings, scenario.expected)
    lines.append(
        "| **overall** | %d | %d | %d | %s | %s |"
        % (overall.true_positives, overall.false_positives, overall.false_negatives, _pct(overall.precision), _pct(overall.recall))
    )
    lines.append("")

    lines.append("## First appearance during replay")
    lines.append("")
    lines.append("| Kind | Policy | User | First as-of |")
    lines.append("|---|---|---|---|")
    first = first_flagged(results)
    for key in sorted(first, key=lambda k: (k[0], -1 if k[1] is None else k[1], k[2] or "")):
        kind, pid, user = key
        lines.append(
            "| %s | %s | %s | %s |"
            % (kind, "" if pid is None else pid, user or "", first[key].strftime("%Y-%m-%d"))
        )
    lines.append("")
    lines.append(
        "Replay window: %d days. Synthetic data only; no live Ranger or Solr was queried."
        % replay_days
    )
    return "\n".join(lines)


def main(argv: Sequence[str] = ()) -> int:
    parser = argparse.ArgumentParser(description="Replay detectors over synthetic audit data.")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--store", default=":memory:", help="SQLite path for the feature store")
    parser.add_argument("--replay-days", type=int, default=30)
    parser.add_argument("--step-days", type=int, default=1)
    args = parser.parse_args(list(argv))

    scenario = build_scenario(seed=args.seed)
    builder = SnapshotBuilder(scenario.source, scenario.source)
    as_ofs = as_of_series(scenario.as_of - timedelta(days=args.replay_days), scenario.as_of, args.step_days)

    with FeatureStore(args.store) as store:
        results = replay(builder, as_ofs, DetectorConfig(), store=store)

    print(render_report(scenario, results, args.replay_days))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
