# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

"""Command line interface, usable as a lego ``exec`` DNS-01 provider."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from pprint import pprint

from . import __version__
from .client import Joker
from .exceptions import JokerError


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="joker-dmapi",
        description="Joker.com DMAPI client. Needs JOKER_API_KEY, or JOKER_USERNAME and JOKER_PASSWORD.",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="log requests and progress")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="mode", required=True)
    sub.add_parser("info", help="show account info and zones")
    for name, what in (("present", "add"), ("cleanup", "remove")):
        s = sub.add_parser(name, help=f"{what} an ACME TXT record (lego exec raw mode)")
        s.add_argument("fqdn", help="record name, e.g. _acme-challenge.example.com.")
        s.add_argument("value", help="TXT value")
    s = sub.add_parser("get-zone", help="print a zone file")
    s.add_argument("domain")
    s = sub.add_parser("put-zone", help="replace a zone with the contents of a file")
    s.add_argument("domain")
    s.add_argument("zone_file", type=Path)
    return p


def _client() -> Joker:
    key = os.environ.get("JOKER_API_KEY", "")
    user = os.environ.get("JOKER_USERNAME", "")
    password = os.environ.get("JOKER_PASSWORD", "")
    if not key and not (user and password):
        msg = "JOKER_API_KEY (or JOKER_USERNAME and JOKER_PASSWORD) must be set"
        raise SystemExit(msg)
    return Joker(api_key=key, username=user, password=password)


def _run(dmapi: Joker, args: argparse.Namespace) -> None:
    match args.mode:
        case "info":
            print("Account info:")
            pprint(dmapi.account_info)
            print("Account domains:")
            for zone in dmapi.dns_zone_list():
                print(f"Domain: {zone.name} Expires: {zone.expires}")
        case "present" | "cleanup":
            found = dmapi.find_domain_for_fqdn(args.fqdn)
            if found is None:
                msg = f"no zone in this account contains {args.fqdn}"
                raise SystemExit(msg)
            domain, record = found
            if args.mode == "present":
                print(f"Adding record '{record}' to domain '{domain}'")
                dmapi.add_txt_record(domain, record, args.value)
            else:
                print(f"Removing record '{record}' from domain '{domain}'")
                dmapi.remove_txt_record(domain, record, args.value)
        case "get-zone":
            print(dmapi.dns_zone_get(args.domain))
        case "put-zone":
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


def main(argv: list[str] | None = None) -> int:
    """Run the CLI; returns the process exit code."""
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)
    try:
        with _client() as dmapi:
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
