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

"""Checks who is approving, rejecting, reconciling or rolling back.

A name typed on the command line proves nothing. With the default
RANGER_AI_REVIEWER_AUTH=ranger, the person's own Ranger credentials are sent
to Ranger Admin's GET /service/users/profile, and the login name Ranger returns
is the one recorded. That account must hold ROLE_SYS_ADMIN and must not be the
agent's own service account.

RANGER_AI_REVIEWER_AUTH=none records the typed name as "unverified". Approvals
recorded that way are not applied; use it only for demos and tests.

Only HTTP basic authentication is supported. A Ranger Admin that accepts only
Kerberos or SSO logins cannot check reviewers yet.
"""

import getpass
import os
import sys
from dataclasses import dataclass
from typing import Any, Callable, Optional

import requests

from ranger_ai_agent.config import RangerConfig

PROFILE_PATH = "/service/users/profile"
ROLE_SYS_ADMIN = "ROLE_SYS_ADMIN"
REVIEWER_AUTH_ENV = "RANGER_AI_REVIEWER_AUTH"
REVIEWER_PASSWORD_ENV = "RANGER_AI_REVIEWER_PASSWORD"

AUTH_RANGER = "ranger"  # login checked against Ranger Admin
AUTH_UNVERIFIED = "unverified"  # typed name only


class ReviewerAuthError(ValueError):
    """The reviewer could not be confirmed."""


@dataclass(frozen=True)
class Reviewer:
    login: str
    auth: str


def check_reviewer(config: RangerConfig, login: str, password: str, session: Optional[Any] = None) -> Reviewer:
    """Confirm `login` with Ranger Admin using that person's own password."""
    login = (login or "").strip()
    if not login or not password:
        raise ReviewerAuthError("a reviewer login and password are required")
    if config.username and login.casefold() == config.username.strip().casefold():
        raise ReviewerAuthError("the agent's service account cannot review its own suggestions")

    session = session or requests.Session()
    url = config.base_url.rstrip("/") + PROFILE_PATH
    try:
        response = session.get(
            url,
            auth=(login, password),
            headers={"Accept": "application/json"},
            timeout=config.timeout_seconds,
            verify=config.verify_tls,
            allow_redirects=False,  # a redirect to a login page is a failure, not a profile
        )
    except requests.RequestException as exc:
        raise ReviewerAuthError("could not reach Ranger Admin to check the reviewer: %s" % exc) from exc

    if response.status_code in (401, 403):
        raise ReviewerAuthError("Ranger Admin did not accept the credentials for %s" % login)
    if response.status_code != 200:
        raise ReviewerAuthError("Ranger Admin returned HTTP %d when checking the reviewer" % response.status_code)
    try:
        profile = response.json()
    except ValueError as exc:
        raise ReviewerAuthError("Ranger Admin returned no user profile for %s" % login) from exc
    if not isinstance(profile, dict):
        raise ReviewerAuthError("Ranger Admin returned no user profile for %s" % login)

    confirmed = str(profile.get("loginId") or "").strip()
    if confirmed.casefold() != login.casefold():
        raise ReviewerAuthError("Ranger Admin returned the profile of a different user")
    roles = profile.get("userRoleList") or []
    if not isinstance(roles, list) or ROLE_SYS_ADMIN not in roles:
        raise ReviewerAuthError("%s is not a Ranger system administrator (%s)" % (confirmed, ROLE_SYS_ADMIN))
    if config.username and confirmed.casefold() == config.username.strip().casefold():
        raise ReviewerAuthError("the agent's service account cannot review its own suggestions")
    return Reviewer(confirmed, AUTH_RANGER)


def reviewer_from_env(
    config: RangerConfig,
    login: str,
    prompt: Callable[[str], str] = getpass.getpass,
    interactive: Optional[bool] = None,
) -> Reviewer:
    """Check the reviewer as RANGER_AI_REVIEWER_AUTH says. The password comes from
    RANGER_AI_REVIEWER_PASSWORD, or a prompt when run from a terminal."""
    mode = os.environ.get(REVIEWER_AUTH_ENV, AUTH_RANGER).strip().lower()
    if mode == "none":
        return Reviewer((login or "").strip(), AUTH_UNVERIFIED)
    if mode != AUTH_RANGER:
        raise ValueError("%s must be 'ranger' or 'none'" % REVIEWER_AUTH_ENV)

    password = os.environ.get(REVIEWER_PASSWORD_ENV)
    if not password:
        if interactive is None:
            interactive = sys.stdin.isatty()
        if not interactive:
            raise ReviewerAuthError("set %s, or run from a terminal to be asked for the password" % REVIEWER_PASSWORD_ENV)
        password = prompt("Ranger password for %s: " % (login or "").strip())
    return check_reviewer(config, login, password)
