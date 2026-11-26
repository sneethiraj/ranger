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

"""Domain models shared by the feature store, detectors and replay harness."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

UTC = timezone.utc
_ISO_SECONDS = "%Y-%m-%dT%H:%M:%SZ"


def ensure_utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime; naive values are assumed to be UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def format_utc(value: datetime) -> str:
    return ensure_utc(value).strftime(_ISO_SECONDS)


def parse_utc(value: str) -> datetime:
    return datetime.strptime(value, _ISO_SECONDS).replace(tzinfo=UTC)


def parse_ranger_time(value: Any) -> Optional[datetime]:
    """Ranger serializes timestamps as epoch milliseconds or as ISO-8601 text.

    Returned values are whole-second UTC datetimes so they round-trip through
    the feature store without loss.
    """
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError("boolean is not a timestamp: %r" % (value,))
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000.0, tz=UTC).replace(microsecond=0)
    if isinstance(value, str):
        text = value.strip()
        if text.lstrip("-").isdigit():
            return datetime.fromtimestamp(int(text) / 1000.0, tz=UTC).replace(microsecond=0)
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return ensure_utc(parsed).replace(microsecond=0)
    raise ValueError("unsupported timestamp: %r" % (value,))


@dataclass(frozen=True)
class PolicyRecord:
    """The parts of a Ranger policy the detectors need."""

    policy_id: int
    name: str
    service: str
    enabled: bool
    created: Optional[datetime]
    updated: Optional[datetime]
    allow_users: Tuple[str, ...] = ()
    allow_groups: Tuple[str, ...] = ()

    def last_changed(self) -> Optional[datetime]:
        times = [t for t in (self.created, self.updated) if t is not None]
        return max(times) if times else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "service": self.service,
            "enabled": self.enabled,
            "created": format_utc(self.created) if self.created is not None else None,
            "updated": format_utc(self.updated) if self.updated is not None else None,
            "allow_users": list(self.allow_users),
            "allow_groups": list(self.allow_groups),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyRecord":
        return cls(
            policy_id=int(data["policy_id"]),
            name=str(data["name"]),
            service=str(data["service"]),
            enabled=bool(data["enabled"]),
            created=parse_utc(data["created"]) if data.get("created") else None,
            updated=parse_utc(data["updated"]) if data.get("updated") else None,
            allow_users=tuple(data.get("allow_users", [])),
            allow_groups=tuple(data.get("allow_groups", [])),
        )


def parse_policy(raw: Dict[str, Any]) -> PolicyRecord:
    """Extract a PolicyRecord from a Ranger public API v2 policy object.

    Only allow items are considered. An item counts when at least one of its
    accesses is allowed. Deny items and exceptions are ignored.
    """
    users = set()
    groups = set()
    for item in raw.get("policyItems") or []:
        accesses = item.get("accesses") or []
        if not any(access.get("isAllowed", True) for access in accesses):
            continue
        users.update(item.get("users") or [])
        groups.update(item.get("groups") or [])

    return PolicyRecord(
        policy_id=int(raw["id"]),
        name=str(raw.get("name", "")),
        service=str(raw.get("service", "")),
        enabled=bool(raw.get("isEnabled", True)),
        created=parse_ranger_time(raw.get("createTime")),
        updated=parse_ranger_time(raw.get("updateTime")),
        allow_users=tuple(sorted(users)),
        allow_groups=tuple(sorted(groups)),
    )


@dataclass(frozen=True)
class UsageStat:
    """Allowed-event count and last allowed time, as reported by the audit store."""

    count: int
    last: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"count": self.count, "last": self.last}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UsageStat":
        return cls(count=int(data["count"]), last=data.get("last"))
