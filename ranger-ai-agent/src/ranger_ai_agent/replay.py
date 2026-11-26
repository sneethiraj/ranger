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

"""Replay harness: re-runs detection as of many historical instants.

Each as-of instant gets a snapshot, which is read from the feature store when
present and built from the audit source otherwise. Replaying the same range
again therefore does not query the audit store.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ranger_ai_agent.detectors import DetectorConfig, Finding, run_detectors
from ranger_ai_agent.features.snapshot import SnapshotBuilder, normalize_as_of
from ranger_ai_agent.features.store import FeatureStore

ExpectedKey = Tuple[str, Optional[int], Optional[str]]


@dataclass(frozen=True)
class ReplayResult:
    as_of: datetime
    findings: Tuple[Finding, ...]


def as_of_series(start: datetime, end: datetime, step_days: int = 1) -> List[datetime]:
    if step_days < 1:
        raise ValueError("step_days must be at least 1")
    current = normalize_as_of(start)
    last = normalize_as_of(end)
    series: List[datetime] = []
    while current <= last:
        series.append(current)
        current += timedelta(days=step_days)
    return series


def replay(
    builder: SnapshotBuilder,
    as_ofs: Iterable[datetime],
    config: Optional[DetectorConfig] = None,
    store: Optional[FeatureStore] = None,
) -> List[ReplayResult]:
    results: List[ReplayResult] = []
    for as_of in as_ofs:
        snap = None
        if store is not None:
            snap = store.load(as_of, builder.lookback_days, builder.recent_days, builder.baseline_days)
        if snap is None:
            snap = builder.build(as_of)
            if store is not None:
                store.save(snap)
        results.append(ReplayResult(as_of=snap.as_of, findings=tuple(run_detectors(snap, config))))
    return results


def first_flagged(results: Sequence[ReplayResult]) -> Dict[Tuple[str, Optional[int], Optional[str]], datetime]:
    """Earliest as-of instant at which each finding key appeared."""
    first: Dict[Tuple[str, Optional[int], Optional[str]], datetime] = {}
    for result in results:
        for finding in result.findings:
            first.setdefault(finding.key, result.as_of)
    return first


@dataclass(frozen=True)
class Metrics:
    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        """Share of findings that match planted anomalies. 1.0 when there are no findings."""
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 1.0

    @property
    def recall(self) -> float:
        """Share of planted anomalies that were found. 1.0 when none are planted."""
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 1.0


def evaluate(findings: Iterable[Finding], expected: Iterable[ExpectedKey]) -> Metrics:
    predicted: Set[ExpectedKey] = {f.key for f in findings}
    expected_set: Set[ExpectedKey] = set(expected)
    return Metrics(
        true_positives=len(predicted & expected_set),
        false_positives=len(predicted - expected_set),
        false_negatives=len(expected_set - predicted),
    )
