# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

"""Parsing of DMAPI text responses."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import NamedTuple

_OK_CODES = frozenset({0, *range(1000, 2000)})
_HEADER_SPLIT = re.compile(r"\s*:\s*")


class Status(NamedTuple):
    """DMAPI Status-Code and Status-Text."""

    code: int
    text: str


@dataclass(frozen=True)
class JokerResponse:
    """A DMAPI response: a block of ``Key: value`` headers, a blank line, then a body."""

    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    @classmethod
    def parse(cls, message: str) -> JokerResponse:
        """Split a raw response at the first blank line.

        Everything after that line is body, including any further blank lines.
        A zone file can contain them, and cutting the body short would make
        a later ``dns-zone-put`` drop records.
        """
        head, _, body = message.replace("\r\n", "\n").partition("\n\n")
        headers: dict[str, str] = {}
        for line in head.splitlines():
            key, *rest = _HEADER_SPLIT.split(line, maxsplit=1)
            headers[key] = rest[0] if rest else ""
        return cls(headers=headers, body=body.rstrip("\n"))

    @property
    def status(self) -> Status:
        """Status-Code and Status-Text; code is -1 when the header is missing."""
        code = int(self.headers["Status-Code"]) if "Status-Code" in self.headers else -1
        return Status(code, self.headers.get("Status-Text", ""))

    @property
    def ok(self) -> bool:
        """True when Status-Code is 0 or in 1000-1999, the range DMAPI documents as success."""
        return self.status.code in _OK_CODES

    def as_list(self) -> list[str]:
        """Body lines."""
        return self.body.splitlines()

    def as_rows(self) -> list[list[str]]:
        """Body lines split by the response's Separator (TAB or a space)."""
        sep = "\t" if self.headers.get("Separator") == "TAB" else " "
        return [line.split(sep) for line in self.body.splitlines()]

    def as_dicts(self) -> list[dict[str, str]]:
        """Rows keyed by the names in the Columns header; empty without that header."""
        if "Columns" not in self.headers:
            return []
        columns = self.headers["Columns"].split(",")
        return [dict(zip(columns, row, strict=False)) for row in self.as_rows()]
