# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

"""Client for the Joker.com DMAPI."""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

import requests

from .exceptions import (
    JokerAPIError,
    JokerAuthError,
    JokerBackupError,
    JokerConnectionError,
    JokerError,
)
from .response import JokerResponse

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from types import TracebackType
    from typing import Any, Self

log = logging.getLogger(__name__)

DEFAULT_URL = "https://dmapi.joker.com"
DEFAULT_TIMEOUT = 30.0
# Properties documented for domain-get-property and domain-set-property.
DOMAIN_PROPERTIES = ("autorenew", "whois-opt-out", "privacy", "gdpr-opt-in")
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


@dataclass(frozen=True)
class AccountBalance:
    """Result of ``query-account-balance``."""

    available: Decimal
    pending: Decimal
    total: Decimal
    currency: str


def _params(**kwargs: Any) -> dict[str, str]:  # noqa: ANN401
    """Build request parameters: None and False are dropped, True becomes "1", ``_`` becomes ``-``."""
    out: dict[str, str] = {}
    for key, value in kwargs.items():
        if value is None or value is False or value == "":
            continue
        out[key.rstrip("_").replace("_", "-")] = "1" if value is True else str(value)
    return out


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
        *,
        url: str = DEFAULT_URL,
        timeout: float = DEFAULT_TIMEOUT,
        backup_dir: Path | str | None = None,
    ) -> None:
        """Create a client; either ``api_key`` or ``username`` and ``password`` is required.

        With ``backup_dir`` set, the current zone is saved there before every zone write.
        """
        if not api_key and not (username and password):
            msg = "api_key or username/password must be defined"
            raise ValueError(msg)
        self.api_key = api_key
        self.username = username
        self.password = password
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.backup_dir = Path(backup_dir) if backup_dir else None
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
        response = self._checked("dns-zone-list", _params(pattern=pattern))
        return [Zone(row[0], row[1] if len(row) > 1 else "") for row in response.as_rows() if row]

    def dns_zone_get(self, domain: str, *, include_defaults: bool = False) -> str:
        """Return the zone file of ``domain``."""
        if not domain:
            msg = "domain must be specified"
            raise ValueError(msg)
        return self._checked("dns-zone-get", _params(domain=domain, include_defaults=include_defaults)).body

    def dns_zone_put(self, domain: str, zone: str) -> JokerResponse:
        """Replace the zone file of ``domain``, saving the current one first if backups are on."""
        return self._replace_zone(domain, zone, current=None)

    def backup_zone(self, domain: str, zone: str | None = None) -> Path:
        """Save ``zone`` (default: the current zone) to ``backup_dir`` and return the file path.

        Files are named ``<domain>-<UTC timestamp>.zone`` and are readable by the owner only,
        since a zone can hold DynDNS credentials.
        """
        if self.backup_dir is None:
            msg = "backup_dir is not set"
            raise ValueError(msg)
        if zone is None:
            zone = self.dns_zone_get(domain)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
        path = self.backup_dir / f"{re.sub(r'[^A-Za-z0-9._-]', '_', domain)}-{stamp}.zone"
        try:
            self.backup_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(zone + "\n")
        except OSError as e:
            msg = f"can't write zone backup {path}: {e}"
            raise JokerBackupError(msg) from e
        log.info("saved zone backup %s", path)
        return path

    def _replace_zone(self, domain: str, zone: str, current: str | None) -> JokerResponse:
        if not domain or not zone:
            msg = "domain and zone must not be empty"
            raise ValueError(msg)
        if self.backup_dir is not None:
            self.backup_zone(domain, current)
        return self._checked("dns-zone-put", {"domain": domain, "zone": zone}, post=True)

    # Read-only requests. Names follow the official DMAPI request names.

    def query_profile(self) -> dict[str, str]:
        """Reseller profile data."""
        return self._checked("query-profile").as_dict()

    def query_account_balance(self) -> AccountBalance:
        """Available, pending and total balance."""
        rows = self._checked("query-account-balance").as_table(("available", "pending", "total", "currency"))
        if not rows:
            msg = "query-account-balance: empty response"
            raise JokerError(msg)
        row = rows[0]
        return AccountBalance(
            Decimal(row["available"]), Decimal(row["pending"]), Decimal(row["total"]), row["currency"]
        )

    def query_order_list(self, **filters: Any) -> list[dict[str, str]]:  # noqa: ANN401
        """Orders, as dicts keyed by column. Filters are the documented parameters.

        Use underscores for dashes (``fqdn_like``, ``show_all``); ``after`` and ``before``
        take ``YYYY-MM-DD``. Without filters the last 30 days are returned.
        """
        return self._checked("query-order-list", _params(**filters)).as_table()

    def result_list(self, **filters: Any) -> list[list[str]]:  # noqa: ANN401
        """Results of asynchronous requests, one list of fields per row.

        Fields are timestamp, SvTrId, Proc-ID, request type, status and ClTrId; an
        object name may follow the type. Filters are the documented parameters.
        """
        return self._checked("result-list", _params(**filters)).as_rows()

    def result_retrieve(self, proc_id: str = "", svtrid: str = "") -> JokerResponse:
        """Full answer for an earlier request, by processing id or SvTrId (which wins)."""
        if not proc_id and not svtrid:
            msg = "proc_id or svtrid must be given"
            raise ValueError(msg)
        # SvTrId has precedence, so send only that one when both are given.
        params = _params(svtrid=svtrid) if svtrid else _params(proc_id=proc_id)
        return self._checked("result-retrieve", params)

    def query_domain_list(
        self,
        pattern: str = "",
        *,
        show_status: bool = False,
        show_grants: bool = False,
        show_privacy: bool = False,
        from_: int | None = None,
        to: int | None = None,
    ) -> list[dict[str, str]]:
        """Domains in the account with their expiry date, plus the extra columns asked for."""
        columns = ["domain", "expires"]
        if show_status:
            columns.append("status")
        if show_grants:
            columns.append("grants")
        if show_privacy:
            columns += ["privacy-status", "privacy-origin", "privacy-expiration"]
        params = _params(
            pattern=pattern,
            showstatus=show_status,
            showgrants=show_grants,
            showprivacy=show_privacy,
            **{"from": from_, "to": to},
        )
        return self._checked("query-domain-list", params).as_table(columns)

    def query_ns_list(self, pattern: str = "", *, full: bool = False) -> list[dict[str, str]]:
        """List registered name servers; ``full`` adds IPv4 and IPv6 addresses ("-" if absent)."""
        columns = ("host", "ipv4", "ipv6") if full else ("host",)
        return self._checked("query-ns-list", _params(pattern=pattern, full=full)).as_table(columns)

    def query_contact_list(
        self, pattern: str = "", *, tld: str = "", extended: bool = False
    ) -> list[dict[str, str]]:
        """Contact handles, with name and organization when ``extended``."""
        columns = ("handle", "name", "organization") if extended else ("handle",)
        params = _params(pattern=pattern, tld=tld, extended_format=extended)
        return self._checked("query-contact-list", params).as_table(columns)

    def domain_check(
        self, domain: str, *, check_price: str = "", period: int | None = None, language: str = ""
    ) -> dict[str, str]:
        """Availability and prices (``check_price``: create, renew, transfer or restore)."""
        params = _params(domain=domain, check_price=check_price, period=period, language=language)
        return self._checked("domain-check", params).as_dict()

    def domain_get_property(self, domain: str, pname: str) -> str:
        """Value of a domain property such as ``autorenew``."""
        response = self._checked("domain-get-property", _params(domain=domain, pname=pname))
        return response.as_dict().get(pname, "")

    def domain_get_properties(self, domain: str, names: Sequence[str] = DOMAIN_PROPERTIES) -> dict[str, str]:
        """Query several properties, one request each.

        DMAPI has no request that returns all properties, so ``names`` defaults to the
        documented list. The first name is queried strictly: any API error, such as an unknown
        domain or an expired session, is raised. Later names that the domain doesn't support
        are left out of the result.
        """
        first, *others = names
        result = {first: self.domain_get_property(domain, first)}
        for name in others:
            try:
                result[name] = self.domain_get_property(domain, name)
            except JokerAPIError as e:
                log.debug("property %s not available for %s: %s", name, domain, e)
        return result

    def grants_list(self, domain: str, *, show_key: bool = False) -> list[list[str]]:
        """Grants and pending invitations of a domain, one list of fields per row."""
        return self._checked("grants-list", _params(domain=domain, showkey=show_key)).as_rows()

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
        current = self.dns_zone_get(domain)
        lines = [*current.splitlines(), f'{record} TXT 0 "{value}" {int(ttl)}']
        self._replace_zone(domain, "\n".join(lines), current)

    def remove_txt_record(self, domain: str, record: str, value: str = "") -> bool:
        """Remove TXT records named ``record``; only those holding ``value`` if it is given.

        Returns False, without writing, when nothing matched.
        """
        if not domain or not record:
            msg = "domain and record can't be empty"
            raise ValueError(msg)
        current = self.dns_zone_get(domain)
        lines = current.splitlines()
        kept = [line for line in lines if not _matches(line, record, value)]
        if len(kept) == len(lines):
            return False
        self._replace_zone(domain, "\n".join(kept), current)
        return True


def _matches(line: str, record: str, value: str) -> bool:
    m = _TXT_LINE.match(line.strip())
    if m is None:
        return False
    return m["label"] == record and (not value or m["value"].strip() == value)
