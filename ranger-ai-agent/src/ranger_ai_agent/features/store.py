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

"""SQLite-backed store for feature snapshots.

Snapshots are keyed by (as_of, lookback_days, recent_days, baseline_days).
Saving the same key again replaces its features, so repeated replays are
idempotent.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Optional

from ranger_ai_agent.features.snapshot import FeatureSnapshot, normalize_as_of
from ranger_ai_agent.models import UTC, format_utc

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    as_of         TEXT    NOT NULL,
    lookback_days INTEGER NOT NULL,
    recent_days   INTEGER NOT NULL,
    baseline_days INTEGER NOT NULL,
    created_at    TEXT    NOT NULL,
    UNIQUE (as_of, lookback_days, recent_days, baseline_days)
);
CREATE TABLE IF NOT EXISTS features (
    snapshot_id  INTEGER NOT NULL REFERENCES snapshots (snapshot_id) ON DELETE CASCADE,
    feature_type TEXT    NOT NULL,
    entity_key   TEXT    NOT NULL,
    payload      TEXT    NOT NULL,
    PRIMARY KEY (snapshot_id, feature_type, entity_key)
);
"""

_KEY_WHERE = "as_of = ? AND lookback_days = ? AND recent_days = ? AND baseline_days = ?"


class FeatureStore:
    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(SCHEMA)

    def __enter__(self) -> "FeatureStore":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def save(self, snap: FeatureSnapshot) -> int:
        key = (format_utc(snap.as_of), snap.lookback_days, snap.recent_days, snap.baseline_days)
        with self._conn:
            row = self._conn.execute("SELECT snapshot_id FROM snapshots WHERE " + _KEY_WHERE, key).fetchone()
            if row is None:
                cursor = self._conn.execute(
                    "INSERT INTO snapshots (as_of, lookback_days, recent_days, baseline_days, created_at) VALUES (?, ?, ?, ?, ?)",
                    key + (format_utc(datetime.now(UTC)),),
                )
                snapshot_id = cursor.lastrowid
            else:
                snapshot_id = row[0]
                self._conn.execute("DELETE FROM features WHERE snapshot_id = ?", (snapshot_id,))

            self._conn.executemany(
                "INSERT INTO features (snapshot_id, feature_type, entity_key, payload) VALUES (?, ?, ?, ?)",
                [(snapshot_id, ftype, key_, payload) for ftype, key_, payload in snap.to_feature_rows()],
            )
        return snapshot_id

    def load(self, as_of: datetime, lookback_days: int, recent_days: int, baseline_days: int) -> Optional[FeatureSnapshot]:
        as_of = normalize_as_of(as_of)
        row = self._conn.execute(
            "SELECT snapshot_id FROM snapshots WHERE " + _KEY_WHERE,
            (format_utc(as_of), lookback_days, recent_days, baseline_days),
        ).fetchone()
        if row is None:
            return None
        rows = self._conn.execute(
            "SELECT feature_type, entity_key, payload FROM features WHERE snapshot_id = ?",
            (row[0],),
        ).fetchall()
        return FeatureSnapshot.from_feature_rows(as_of, lookback_days, recent_days, baseline_days, rows)

    def snapshot_count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0])
