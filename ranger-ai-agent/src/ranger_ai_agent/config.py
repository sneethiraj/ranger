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

"""Configuration loaded from environment variables.

Secrets are never read from files in this module; supply them through the
environment (or a secret manager that populates it).
"""

import os
from dataclasses import dataclass, field
from typing import Optional, Union


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_verify(name: str, default: bool) -> Union[bool, str]:
    """TLS verification: true/false, or a path to a CA bundle."""
    value = os.environ.get(name)
    if value is None:
        return default
    lowered = value.strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    return value  # CA bundle path


@dataclass
class RangerConfig:
    base_url: str = "http://localhost:6080"
    username: str = ""
    password: str = field(default="", repr=False)
    verify_tls: Union[bool, str] = True
    timeout_seconds: float = 30.0
    page_size: int = 500

    @classmethod
    def from_env(cls) -> "RangerConfig":
        return cls(
            base_url=os.environ.get("RANGER_AI_RANGER_URL", cls.base_url),
            username=os.environ.get("RANGER_AI_RANGER_USER", ""),
            password=os.environ.get("RANGER_AI_RANGER_PASSWORD", ""),
            verify_tls=_env_verify("RANGER_AI_RANGER_VERIFY_TLS", True),
            timeout_seconds=float(os.environ.get("RANGER_AI_RANGER_TIMEOUT", cls.timeout_seconds)),
            page_size=int(os.environ.get("RANGER_AI_RANGER_PAGE_SIZE", cls.page_size)),
        )


@dataclass
class SolrConfig:
    base_url: str = "http://localhost:6083/solr"
    collection: str = "ranger_audits"
    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    verify_tls: Union[bool, str] = True
    timeout_seconds: float = 60.0

    @classmethod
    def from_env(cls) -> "SolrConfig":
        return cls(
            base_url=os.environ.get("RANGER_AI_SOLR_URL", cls.base_url),
            collection=os.environ.get("RANGER_AI_SOLR_COLLECTION", cls.collection),
            username=os.environ.get("RANGER_AI_SOLR_USER") or None,
            password=os.environ.get("RANGER_AI_SOLR_PASSWORD") or None,
            verify_tls=_env_verify("RANGER_AI_SOLR_VERIFY_TLS", True),
            timeout_seconds=float(os.environ.get("RANGER_AI_SOLR_TIMEOUT", cls.timeout_seconds)),
        )


@dataclass
class SafetyConfig:
    """Safeguards; defaults are the most restrictive."""

    kill_switch: bool = False
    dry_run: bool = True

    @classmethod
    def from_env(cls) -> "SafetyConfig":
        return cls(
            kill_switch=_env_bool("RANGER_AI_KILL_SWITCH", False),
            dry_run=_env_bool("RANGER_AI_DRY_RUN", True),
        )
