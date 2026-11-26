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

"""Read-only aggregate queries against the Ranger audit Solr collection.

All methods use Solr's JSON Facet API so aggregation happens inside Solr;
raw audit events are never pulled into memory. Only the /select handler is
used, so the client cannot modify the index.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from ranger_ai_agent.config import SolrConfig

LOG = logging.getLogger(__name__)

RESULT_ALLOWED = 1
RESULT_DENIED = 0


class SolrAuditError(RuntimeError):
    """Raised when Solr returns an error or an unexpected payload."""


@dataclass(frozen=True)
class PolicyUsage:
    """How a policy was exercised in a time window."""

    policy_id: int
    allowed_count: int
    last_allowed: Optional[str]  # ISO-8601 from Solr


@dataclass(frozen=True)
class UserPolicyUsage:
    user: str
    allowed_count: int
    last_allowed: Optional[str]


def to_solr_date(value: datetime) -> str:
    """Format a datetime as the UTC ISO-8601 string Solr expects."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def quote_term(value: str) -> str:
    """Quote a value for safe use inside a Solr filter query.

    Audit values are untrusted; quoting and escaping prevents query injection.
    """
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _time_filter(start: datetime, end: datetime) -> str:
    return "evtTime:[%s TO %s]" % (to_solr_date(start), to_solr_date(end))


class SolrAuditReader:
    def __init__(self, config: SolrConfig, session: Optional[requests.Session] = None):
        self._config = config
        self._session = session or requests.Session()
        self._session.verify = config.verify_tls
        if config.username:
            self._session.auth = (config.username, config.password or "")

    def _select(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = "%s/%s/select" % (self._config.base_url.rstrip("/"), self._config.collection)
        body = dict(params)
        body["wt"] = "json"
        body["rows"] = 0  # aggregates only
        try:
            response = self._session.post(url, data=body, timeout=self._config.timeout_seconds)
        except requests.RequestException as exc:
            raise SolrAuditError("Solr request failed: %s" % exc) from exc

        if response.status_code != 200:
            raise SolrAuditError("Solr returned HTTP %d" % response.status_code)
        try:
            return response.json()
        except ValueError as exc:
            raise SolrAuditError("Solr returned non-JSON body") from exc

    def count(self, start: datetime, end: datetime, *filters: str) -> int:
        """Number of audit events in the window, optionally narrowed by filters."""
        data = self._select({"q": "*:*", "fq": [_time_filter(start, end), *filters]})
        return int(data["response"]["numFound"])

    def policy_usage(self, start: datetime, end: datetime, limit: int = 10000) -> List[PolicyUsage]:
        """Allowed-event count and last allowed time per policy id."""
        facet = {
            "policies": {
                "type": "terms",
                "field": "policy",
                "limit": limit,
                "facet": {"last": "max(evtTime)"},
            }
        }
        data = self._select(
            {
                "q": "*:*",
                "fq": [_time_filter(start, end), "result:%d" % RESULT_ALLOWED, "policy:[0 TO *]"],
                "json.facet": json.dumps(facet),
            }
        )
        buckets = data.get("facets", {}).get("policies", {}).get("buckets", [])
        return [
            PolicyUsage(policy_id=int(b["val"]), allowed_count=int(b["count"]), last_allowed=b.get("last"))
            for b in buckets
        ]

    def user_usage_for_policy(
        self, policy_id: int, start: datetime, end: datetime, limit: int = 10000
    ) -> List[UserPolicyUsage]:
        """Allowed-event count and last allowed time per user for one policy."""
        facet = {
            "users": {
                "type": "terms",
                "field": "reqUser",
                "limit": limit,
                "facet": {"last": "max(evtTime)"},
            }
        }
        data = self._select(
            {
                "q": "*:*",
                "fq": [
                    _time_filter(start, end),
                    "result:%d" % RESULT_ALLOWED,
                    "policy:%d" % int(policy_id),
                ],
                "json.facet": json.dumps(facet),
            }
        )
        buckets = data.get("facets", {}).get("users", {}).get("buckets", [])
        return [
            UserPolicyUsage(user=str(b["val"]), allowed_count=int(b["count"]), last_allowed=b.get("last"))
            for b in buckets
        ]

    def hourly_histogram(self, user: str, start: datetime, end: datetime) -> List[int]:
        """Event counts for a user bucketed by hour-of-day (UTC), length 24."""
        facet = {
            "by_hour": {
                "type": "range",
                "field": "evtTime",
                "start": to_solr_date(start),
                "end": to_solr_date(end),
                "gap": "+1HOUR",
            }
        }
        data = self._select(
            {
                "q": "*:*",
                "fq": [_time_filter(start, end), "reqUser:%s" % quote_term(user)],
                "json.facet": json.dumps(facet),
            }
        )
        histogram = [0] * 24
        buckets = data.get("facets", {}).get("by_hour", {}).get("buckets", [])
        for bucket in buckets:
            hour = _parse_solr_hour(bucket["val"])
            histogram[hour] += int(bucket["count"])
        return histogram

    def active_users(self, start: datetime, end: datetime, limit: int = 10000) -> Dict[str, int]:
        """Event count per user in the window."""
        facet = {"users": {"type": "terms", "field": "reqUser", "limit": limit}}
        data = self._select(
            {
                "q": "*:*",
                "fq": [_time_filter(start, end)],
                "json.facet": json.dumps(facet),
            }
        )
        buckets = data.get("facets", {}).get("users", {}).get("buckets", [])
        return {str(b["val"]): int(b["count"]) for b in buckets}


def _parse_solr_hour(value: str) -> int:
    """Hour-of-day (UTC) from a Solr date string such as 2026-01-02T15:00:00Z."""
    try:
        return datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S").hour
    except ValueError as exc:
        raise SolrAuditError("Unparseable Solr date: %r" % value) from exc
