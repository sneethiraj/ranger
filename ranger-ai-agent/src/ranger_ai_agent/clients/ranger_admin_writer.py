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

"""Write client for Ranger Admin. Used only by the approval-gated applier.

The only write operation is a policy update. Creating and deleting policies,
and changing services, roles or users, are not implemented on purpose.
"""

from typing import Any, Dict, Optional

import requests

from ranger_ai_agent.clients.ranger_admin import PUBLIC_V2, RangerApiError
from ranger_ai_agent.config import RangerConfig


class RangerAdminWriter:
    def __init__(self, config: RangerConfig, session: Optional[requests.Session] = None):
        self._config = config
        self._session = session or requests.Session()
        self._session.verify = config.verify_tls
        if config.username:
            self._session.auth = (config.username, config.password)
        self._session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

    def update_policy(self, policy_id: int, body: Dict[str, Any]) -> Dict[str, Any]:
        """PUT the full policy object. The body's id must match policy_id."""
        if body.get("id") != policy_id:
            raise ValueError("policy body id %r does not match policy_id %r" % (body.get("id"), policy_id))
        path = "%s/policy/%d" % (PUBLIC_V2, policy_id)
        url = self._config.base_url.rstrip("/") + path
        try:
            response = self._session.put(url, json=body, timeout=self._config.timeout_seconds)
        except requests.RequestException as exc:
            raise RangerApiError("PUT %s failed: %s" % (path, type(exc).__name__)) from exc
        if response.status_code != 200:
            raise RangerApiError("PUT %s returned HTTP %d" % (path, response.status_code))
        try:
            return response.json()
        except ValueError as exc:
            raise RangerApiError("PUT %s returned non-JSON body" % path) from exc
