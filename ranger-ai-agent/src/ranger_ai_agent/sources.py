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

"""Structural interfaces for the data the snapshot builder reads.

The live clients (SolrAuditReader, RangerAdminReader) satisfy these protocols,
and so does the in-memory synthetic source used for replay and tests.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Protocol

from ranger_ai_agent.clients.solr_audit import PolicyUsage, UserPolicyUsage


class AuditSource(Protocol):
    def policy_usage(self, start: datetime, end: datetime) -> List[PolicyUsage]: ...

    def user_usage_for_policy(self, policy_id: int, start: datetime, end: datetime) -> List[UserPolicyUsage]: ...

    def hourly_histogram(self, user: str, start: datetime, end: datetime) -> List[int]: ...

    def active_users(self, start: datetime, end: datetime) -> Dict[str, int]: ...


class PolicySource(Protocol):
    def list_policies(self, service_name: Optional[str] = None) -> List[Dict[str, Any]]: ...
