# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

"""Client for the Joker.com DMAPI."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, NamedTuple

import requests

from .exceptions import JokerAPIError, JokerAuthError, JokerConnectionError, JokerError
from .response import JokerResponse

if TYPE_CHECKING:
    from collections.abc import Mapping
    from types import TracebackType
    from typing import Self

log = logging.getLogger(__name__)

DEFAULT_URL = "https://dmapi.joker.com"
DEFAULT_TIMEOUT = 30.0
_ACCOUNT_HEADERS = (
    "Account-balance",
    "Account-contract_date",
    "Account-currency",
    "Account-rebate",
    "UID",
    "User-Access",
    "User-Login",
)
_TXT_LINE = re.compile(r'^(?P<label>\S+)\s+TXT\s+\d+\s+"(?P<value>.*?)"(?:\s+\d+)?\s*$', re.IGNORECASE)
_FORBIDDEN = re.compile(r'[\x00-\x1f"\\]')


class Zone(NamedTuple):
    """A domain with a DNS zone and its expiry date."""

    name: str
    expires: str


def split_fqdn(fqdn: str, zones: list[str]) -> tuple[str, str] | None:
    """Find the longest zone containing ``fqdn`` and return ``(zone, label)``.

    The label is ``@`` for the zone apex. Returns None when no zone matches.
    A zone only matches on a whole label, so ``example.com`` does not match
    ``foo.notexample.com``.
    """
    name = fqdn.rstrip(".").lower()
    best = ""
    for zone in zones:
        z = zone.rstrip(".").lower()
        if (name == z or name.endswith("." + z)) and len(z) > len(best):
            best = z
    if not best:
        return None
    return best, "@" if name == best else name[: -len(best) - 1]


class Joker:
    """DMAPI session. Use it as a context manager so the session is always closed."""

    def __init__(
        self,
        api_key: str = "",
        username: str = "",
        password: str = "",
        url: str = DEFAULT_URL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        """Create a client; either ``api_key`` or ``username`` and ``password`` is required."""
        if not api_key and not (username and password):
            msg = "api_key or username/password must be defined"
            raise ValueError(msg)
        self.api_key = api_key
        self.username = username
        self.password = password
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.auth_sid = ""
        self.supported_domains: list[str] = []
        self.account_info: dict[str, str] = {}
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "Joker python DMAPI"

    def __enter__(self) -> Self:
        """Log in."""
        self.login()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Log out. A failed logout is logged and never hides the original error."""
        try:
            self.logout()
        except JokerError as e:
            log.warning("logout failed: %s", e)
        finally:
            self._session.close()

    def request(
        self, command: str, params: Mapping[str, str] | None = None, *, post: bool = False
    ) -> JokerResponse:
        """Send a command and return the parsed response without checking Status-Code."""
        data = dict(params or {})
        if self.auth_sid:
            data["auth-sid"] = self.auth_sid
        url = f"{self.url}/request/{command}"
        try:
            # Redirects are not followed: DMAPI answers 200, and a redirect could send auth-sid elsewhere.
            if post:
                resp = self._session.post(url, data=data, timeout=self.timeout, allow_redirects=False)
            else:
                resp = self._session.get(url, params=data, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException as e:
            msg = f"{command}: {e}"
            raise JokerConnectionError(msg) from e
        if resp.status_code != requests.codes.ok:
            msg = f"{command}: unexpected HTTP status {resp.status_code}"
            raise JokerConnectionError(msg)
        if command != "login":  # the login reply carries the session id and account details
            log.debug("%s reply:\n%s", command, resp.text)
        return JokerResponse.parse(resp.text)

    def _checked(
        self, command: str, params: Mapping[str, str] | None = None, *, post: bool = False
    ) -> JokerResponse:
        response = self.request(command, params, post=post)
        if not response.ok:
            raise JokerAPIError(*response.status, response.headers)
        return response

    def login(self) -> JokerResponse:
        """Authenticate and store the Auth-Sid. Credentials are sent in a POST body."""
        if self.api_key:
            params = {"api-key": self.api_key}
        else:
            params = {"username": self.username, "password": self.password}
        response = self.request("login", params, post=True)
        if not response.ok:
            raise JokerAuthError(*response.status, response.headers)
        if "Auth-Sid" not in response.headers:
            raise JokerAuthError(-1, "no Auth-Sid in login response", response.headers)
        self.auth_sid = response.headers["Auth-Sid"]
        self.account_info = {k: response.headers[k] for k in _ACCOUNT_HEADERS if k in response.headers}
        self.supported_domains = response.as_list()
        return response

    def logout(self) -> None:
        """End the session; does nothing when not logged in."""
        if not self.auth_sid:
            return
        try:
            self._checked("logout")
        finally:
            self.auth_sid = ""
            self.account_info = {}
            self.supported_domains = []

    def dns_zone_list(self, pattern: str = "") -> list[Zone]:
        """List zones, optionally filtered by a glob pattern."""
        response = self._checked("dns-zone-list", {"pattern": pattern} if pattern else None)
        return [Zone(row[0], row[1] if len(row) > 1 else "") for row in response.as_rows() if row[0]]

    def dns_zone_get(self, domain: str) -> str:
        """Return the zone file of ``domain``."""
        if not domain:
            msg = "domain must be specified"
            raise ValueError(msg)
        return self._checked("dns-zone-get", {"domain": domain}).body

    def dns_zone_put(self, domain: str, zone: str) -> JokerResponse:
        """Replace the zone file of ``domain``."""
        if not domain or not zone:
            msg = "domain and zone must not be empty"
            raise ValueError(msg)
        return self._checked("dns-zone-put", {"domain": domain, "zone": zone}, post=True)

    def find_domain_for_fqdn(self, fqdn: str) -> tuple[str, str] | None:
        """Map an FQDN to ``(zone, label)`` using this account's zones, or None."""
        return split_fqdn(fqdn, [z.name for z in self.dns_zone_list()])

    def add_txt_record(self, domain: str, record: str, value: str, ttl: int = 60) -> None:
        """Append a TXT record to the zone."""
        if not domain or not record or not value:
            msg = "domain, record and value can't be empty"
            raise ValueError(msg)
        # Quotes, backslashes and control characters would let a value break out of its zone line.
        if _FORBIDDEN.search(record) or _FORBIDDEN.search(value) or re.search(r"\s", record):
            msg = f"unsupported characters in record {record!r} or value {value!r}"
            raise ValueError(msg)
        lines = self.dns_zone_get(domain).splitlines()
        lines.append(f'{record} TXT 0 "{value}" {int(ttl)}')
        self.dns_zone_put(domain, "\n".join(lines))

    def remove_txt_record(self, domain: str, record: str, value: str = "") -> bool:
        """Remove TXT records named ``record``; only those holding ``value`` if it is given.

        Returns False, without writing, when nothing matched.
        """
        if not domain or not record:
            msg = "domain and record can't be empty"
            raise ValueError(msg)
        lines = self.dns_zone_get(domain).splitlines()
        kept = [line for line in lines if not _matches(line, record, value)]
        if len(kept) == len(lines):
            return False
        self.dns_zone_put(domain, "\n".join(kept))
        return True


def _matches(line: str, record: str, value: str) -> bool:
    m = _TXT_LINE.match(line.strip())
    if m is None:
        return False
    return m["label"] == record and (not value or m["value"].strip() == value)
