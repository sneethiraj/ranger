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

"""Read-only client for the Ranger Admin REST API.

This client deliberately exposes only GET operations. Writes (apply and
rollback of approved suggestions) belong to a separate, explicitly
approval-gated component so the read path can never change Ranger state.
"""

import logging
from typing import Any, Dict, Iterator, List, Optional

import requests

from ranger_ai_agent.config import RangerConfig

LOG = logging.getLogger(__name__)

PUBLIC_V2 = "/service/public/v2/api"
XUSERS = "/service/xusers"


class RangerApiError(RuntimeError):
    """Raised when Ranger Admin returns an error or an unexpected payload."""


class RangerAdminReader:
    def __init__(self, config: RangerConfig, session: Optional[requests.Session] = None):
        self._config = config
        self._session = session or requests.Session()
        self._session.verify = config.verify_tls
        if config.username:
            self._session.auth = (config.username, config.password)
        self._session.headers.update({"Accept": "application/json"})

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        url = self._config.base_url.rstrip("/") + path
        try:
            response = self._session.get(url, params=params, timeout=self._config.timeout_seconds)
        except requests.RequestException as exc:
            raise RangerApiError("GET %s failed: %s" % (path, exc)) from exc

        if response.status_code != 200:
            raise RangerApiError("GET %s returned HTTP %d" % (path, response.status_code))
        try:
            return response.json()
        except ValueError as exc:
            raise RangerApiError("GET %s returned non-JSON body" % path) from exc

    def _paged(self, path: str, extra: Optional[Dict[str, Any]] = None) -> Iterator[Dict[str, Any]]:
        """Iterate a list endpoint that supports pageSize/startIndex."""
        page_size = self._config.page_size
        start = 0
        while True:
            params = {"pageSize": page_size, "startIndex": start}
            if extra:
                params.update(extra)
            batch = self._get(path, params)
            if not isinstance(batch, list):
                raise RangerApiError("GET %s: expected a JSON list" % path)
            for item in batch:
                yield item
            if len(batch) < page_size:
                return
            start += page_size

    def list_services(self) -> List[Dict[str, Any]]:
        return list(self._paged(PUBLIC_V2 + "/service"))

    def list_policies(self, service_name: Optional[str] = None) -> List[Dict[str, Any]]:
        extra = {"serviceName": service_name} if service_name else None
        return list(self._paged(PUBLIC_V2 + "/policy", extra))

    def get_policy(self, policy_id: int) -> Dict[str, Any]:
        return self._get("%s/policy/%d" % (PUBLIC_V2, policy_id))

    def list_roles(self) -> List[Dict[str, Any]]:
        return list(self._paged(PUBLIC_V2 + "/roles"))

    def list_zones(self) -> List[Dict[str, Any]]:
        return list(self._paged(PUBLIC_V2 + "/zones"))

    def list_users(self) -> List[Dict[str, Any]]:
        """Users via the xusers API, which wraps results as {"vXUsers": [...]}."""
        users: List[Dict[str, Any]] = []
        page_size = self._config.page_size
        start = 0
        while True:
            body = self._get(XUSERS + "/users", {"pageSize": page_size, "startIndex": start})
            if not isinstance(body, dict):
                raise RangerApiError("GET %s/users: expected a JSON object" % XUSERS)
            batch = body.get("vXUsers", [])
            users.extend(batch)
            if len(batch) < page_size:
                return users
            start += page_size
