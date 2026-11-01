# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

"""Command line interface, usable as a lego ``exec`` DNS-01 provider."""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import sys
from pathlib import Path
from pprint import pprint
from typing import Any

from . import __version__
from .client import DOMAIN_PROPERTIES, Joker
from .exceptions import JokerError
from .response import JokerResponse

ENV_BACKUP_DIR = "JOKER_BACKUP_DIR"


def _add_global_options(p: argparse.ArgumentParser, *, sub: bool) -> None:
    """Add options accepted before and after the command.

    On subcommands the default is SUPPRESS, so a value given before the command isn't overwritten.
    """
    flag_default: Any = argparse.SUPPRESS if sub else False
    path_default: Any = argparse.SUPPRESS if sub else None
    p.add_argument(
        "-v", "--verbose", action="store_true", default=flag_default, help="log requests and progress"
    )
    p.add_argument("--json", action="store_true", default=flag_default, help="print query results as JSON")
    p.add_argument(
        "--backup-dir",
        type=Path,
        default=path_default,
        help="where to save the old zone before a zone write",
    )
    p.add_argument(
        "--no-backup",
        action="store_true",
        default=flag_default,
        help="don't save the old zone before a write",
    )


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="joker-dmapi",
        description="Joker.com DMAPI client. Needs JOKER_API_KEY, or JOKER_USERNAME and JOKER_PASSWORD.",
        epilog=f"Zone backups go to --backup-dir, ${ENV_BACKUP_DIR}, or "
        "$XDG_STATE_HOME/joker-dmapi/backups (default ~/.local/state/joker-dmapi/backups).",
    )
    _add_global_options(p, sub=False)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def add(name: str, help_: str, aliases: list[str] | None = None) -> argparse.ArgumentParser:
        s = sub.add_parser(name, help=help_, aliases=aliases or [])
        s.set_defaults(command=name)
        _add_global_options(s, sub=True)
        return s

    add("info", "show account info and zones")
    for name, what in (("present", "add"), ("cleanup", "remove")):
        s = add(name, f"{what} an ACME TXT record (lego exec default mode)")
        s.add_argument("fqdn", help="record name, e.g. _acme-challenge.example.com.")
        s.add_argument("value", help="TXT value")

    s = add("dns-zone-list", "list DNS zones", ["list-zones"])
    s.add_argument("pattern", nargs="?", default="")
    s = add("dns-zone-get", "print a zone file", ["get-zone"])
    s.add_argument("domain")
    s.add_argument("--include-defaults", action="store_true", help="include default values")
    s = add("dns-zone-put", "replace a zone with the contents of a file", ["put-zone"])
    s.add_argument("domain")
    s.add_argument("zone_file", type=Path)

    add("query-profile", "show reseller profile")
    add("query-account-balance", "show account balance")
    s = add("query-domain-list", "list domains with expiry dates")
    s.add_argument("pattern", nargs="?", default="")
    s.add_argument("--show-status", action="store_true")
    s.add_argument("--show-grants", action="store_true")
    s.add_argument("--show-privacy", action="store_true")
    s = add("query-ns-list", "list registered name servers")
    s.add_argument("pattern", nargs="?", default="")
    s.add_argument("--full", action="store_true", help="include IP addresses")
    s = add("query-contact-list", "list contact handles")
    s.add_argument("pattern", nargs="?", default="")
    s.add_argument("--tld", default="")
    s.add_argument("--extended", action="store_true", help="include name and organization")
    s = add("query-order-list", "list orders (default: last 30 days)")
    for opt in ("after", "before", "type", "status", "tld", "fqdn", "fqdn-like", "limit"):
        s.add_argument(f"--{opt}")
    s.add_argument("--show-all", action="store_true")
    s.add_argument("--asc", action="store_true", help="oldest first")
    s = add("domain-check", "check availability and price")
    s.add_argument("domain")
    s.add_argument("--check-price", choices=["create", "renew", "transfer", "restore"], default="")
    s.add_argument("--period", type=int)
    s = add("domain-get-property", "show one domain property, or all known ones if none is named")
    s.add_argument("domain")
    s.add_argument(
        "pname", nargs="?", default="", help=f"one of: {', '.join(DOMAIN_PROPERTIES)} (default: all)"
    )
    s = add("grants-list", "list grants and invitations of a domain")
    s.add_argument("domain")
    s.add_argument("--show-key", action="store_true")
    s = add("result-list", "list results of asynchronous requests")
    s.add_argument("--pending", action="store_true")
    s.add_argument("--status")
    s.add_argument("--limit")
    s = add("result-retrieve", "show the answer for a request")
    s.add_argument("--proc-id", default="")
    s.add_argument("--svtrid", default="")
    return p


def _backup_dir(args: argparse.Namespace) -> Path | None:
    if args.no_backup:
        return None
    if args.backup_dir:
        return Path(args.backup_dir)
    if ENV_BACKUP_DIR in os.environ:
        return Path(os.environ[ENV_BACKUP_DIR]) if os.environ[ENV_BACKUP_DIR] else None
    try:
        state = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    except RuntimeError:
        msg = f"can't find a backup directory: set {ENV_BACKUP_DIR} or pass --backup-dir or --no-backup"
        raise SystemExit(msg) from None
    return state / "joker-dmapi" / "backups"


def _client(args: argparse.Namespace) -> Joker:
    key = os.environ.get("JOKER_API_KEY", "")
    user = os.environ.get("JOKER_USERNAME", "")
    password = os.environ.get("JOKER_PASSWORD", "")
    if not key and not (user and password):
        msg = "JOKER_API_KEY (or JOKER_USERNAME and JOKER_PASSWORD) must be set"
        raise SystemExit(msg)
    return Joker(api_key=key, username=user, password=password, backup_dir=_backup_dir(args))


def _plain(obj: Any) -> Any:  # noqa: ANN401
    """Turn dataclasses and named tuples into dicts and lists for printing."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if hasattr(obj, "_asdict"):
        return obj._asdict()
    if isinstance(obj, list):
        return [_plain(x) for x in obj]
    return obj


def _emit(data: Any, *, as_json: bool) -> None:  # noqa: ANN401
    data = _plain(data)
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    elif isinstance(data, dict):
        for key, value in data.items():
            print(f"{key}: {value}")
    elif isinstance(data, list) and data and isinstance(data[0], dict):
        print("\t".join(data[0]))
        for row in data:
            print("\t".join(str(v) for v in row.values()))
    elif isinstance(data, list):
        for row in data:
            print("\t".join(row) if isinstance(row, list) else row)
    else:
        print(data)


def _present_or_cleanup(dmapi: Joker, args: argparse.Namespace) -> None:
    found = dmapi.find_domain_for_fqdn(args.fqdn)
    if found is None:
        msg = f"no zone in this account contains {args.fqdn}"
        raise SystemExit(msg)
    domain, record = found
    if args.command == "present":
        print(f"Adding record '{record}' to domain '{domain}'")
        dmapi.add_txt_record(domain, record, args.value)
    else:
        print(f"Removing record '{record}' from domain '{domain}'")
        dmapi.remove_txt_record(domain, record, args.value)


def _put_zone(dmapi: Joker, args: argparse.Namespace) -> None:
    if not args.zone_file.is_file():
        msg = f"{args.zone_file} doesn't exist or is not a regular file"
        raise SystemExit(msg)
    try:
        zone = args.zone_file.read_text().strip()
    except (OSError, UnicodeDecodeError) as e:
        msg = f"can't read {args.zone_file}: {e}"
        raise SystemExit(msg) from e
    if not zone:
        msg = "zone file is empty"
        raise SystemExit(msg)
    dmapi.dns_zone_put(args.domain, zone)


def _run(dmapi: Joker, args: argparse.Namespace) -> None:
    out = args.json
    a = vars(args)
    match args.command:
        case "info":
            zones = dmapi.dns_zone_list()
            if out:
                _emit({"account": dmapi.account_info, "zones": [z._asdict() for z in zones]}, as_json=True)
            else:
                print("Account info:")
                pprint(dmapi.account_info)
                print("Account domains:")
                for zone in zones:
                    print(f"Domain: {zone.name} Expires: {zone.expires}")
        case "present" | "cleanup":
            _present_or_cleanup(dmapi, args)
        case "dns-zone-list":
            _emit(dmapi.dns_zone_list(args.pattern), as_json=out)
        case "dns-zone-get":
            zone_text = dmapi.dns_zone_get(args.domain, include_defaults=args.include_defaults)
            _emit({"domain": args.domain, "zone": zone_text} if out else zone_text, as_json=out)
        case "dns-zone-put":
            _put_zone(dmapi, args)
        case "query-profile":
            _emit(dmapi.query_profile(), as_json=out)
        case "query-account-balance":
            _emit(dmapi.query_account_balance(), as_json=out)
        case "query-domain-list":
            _emit(
                dmapi.query_domain_list(
                    args.pattern,
                    show_status=args.show_status,
                    show_grants=args.show_grants,
                    show_privacy=args.show_privacy,
                ),
                as_json=out,
            )
        case "query-ns-list":
            _emit(dmapi.query_ns_list(args.pattern, full=args.full), as_json=out)
        case "query-contact-list":
            _emit(
                dmapi.query_contact_list(args.pattern, tld=args.tld, extended=args.extended),
                as_json=out,
            )
        case "query-order-list":
            keys = ("after", "before", "type", "status", "tld", "fqdn", "fqdn_like", "limit")
            _emit(
                dmapi.query_order_list(show_all=args.show_all, asc=args.asc, **{k: a[k] for k in keys}),
                as_json=out,
            )
        case "domain-check":
            _emit(
                dmapi.domain_check(args.domain, check_price=args.check_price, period=args.period),
                as_json=out,
            )
        case "domain-get-property":
            if args.pname:
                _emit(dmapi.domain_get_property(args.domain, args.pname), as_json=out)
            else:
                _emit(dmapi.domain_get_properties(args.domain), as_json=out)
        case "grants-list":
            _emit(dmapi.grants_list(args.domain, show_key=args.show_key), as_json=out)
        case "result-list":
            _emit(
                dmapi.result_list(pending=args.pending, status=args.status, limit=args.limit),
                as_json=out,
            )
        case "result-retrieve":
            response: JokerResponse = dmapi.result_retrieve(args.proc_id, args.svtrid)
            _emit({**response.headers, "body": response.body} if out else response.body, as_json=out)


def main(argv: list[str] | None = None) -> int:
    """Run the CLI; returns the process exit code."""
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)
    try:
        with _client(args) as dmapi:
            _run(dmapi, args)
    except JokerError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except SystemExit as e:
        if isinstance(e.code, str):
            print(f"error: {e.code}", file=sys.stderr)
            return 1
        raise
    return 0
