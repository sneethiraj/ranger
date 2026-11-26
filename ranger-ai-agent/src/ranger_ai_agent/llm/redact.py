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

"""Pseudonymization for data sent to language models.

User names are replaced with keyed HMAC pseudonyms before a prompt leaves the
process. The reverse mapping stays in memory and is used only to restore
names in text shown to the administrator.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from typing import Dict, Iterable, Optional

PSEUDONYM_KEY_ENV = "RANGER_AI_PSEUDONYM_KEY"


class Pseudonymizer:
    def __init__(self, key: Optional[bytes] = None) -> None:
        # Without a configured key the pseudonyms change on every restart.
        self._key = key if key else secrets.token_bytes(32)
        self._forward: Dict[str, str] = {}
        self._reverse: Dict[str, str] = {}

    @classmethod
    def from_env(cls) -> "Pseudonymizer":
        value = os.environ.get(PSEUDONYM_KEY_ENV)
        return cls(value.encode("utf-8") if value else None)

    def pseudonym(self, name: str) -> str:
        if name not in self._forward:
            digest = hmac.new(self._key, name.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
            pseudo = "u_" + digest
            self._forward[name] = pseudo
            self._reverse[pseudo] = name
        return self._forward[name]

    def redact_text(self, text: str, names: Iterable[str]) -> str:
        """Replace whole-token occurrences of each name with its pseudonym."""
        for name in sorted({n for n in names if n}, key=len, reverse=True):
            pattern = r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])"
            text = re.sub(pattern, lambda _m, n=name: self.pseudonym(n), text)
        return text

    def reveal(self, text: str) -> str:
        """Restore real names in text returned by a model. Unknown pseudonyms are left as-is."""
        for pseudo, name in self._reverse.items():
            text = text.replace(pseudo, name)
        return text
