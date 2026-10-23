# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

"""Parsing of DMAPI text responses."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import NamedTuple

_OK_CODES = frozenset({0, *range(1000, 2000)})
_PROTOCOL_HEADERS = frozenset(
    {
        "status-code",
        "status-text",
        "tracking-id",
        "result",
        "error",
        "warning",
        "proc-id",
        "auth-sid",
        "separator",
        "columns",
        "row-count",
        "svtrid",
        "timing",
    }
)
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
        """Body lines split into fields.

        Fields are tab separated when the Separator header says TAB or the line holds a tab
        (empty fields are kept), otherwise they are split on whitespace.
        """
        tab = self.headers.get("Separator") == "TAB"
        return [line.split("\t") if tab or "\t" in line else line.split() for line in self.body.splitlines()]

    def as_table(self, default_columns: Sequence[str] = ()) -> list[dict[str, str]]:
        """Rows keyed by the Columns header, or by ``default_columns`` when the header is absent.

        Fields beyond the known column names are keyed ``col<N>``.
        """
        columns = self.headers["Columns"].split(",") if "Columns" in self.headers else list(default_columns)
        return [
            {columns[i] if i < len(columns) else f"col{i + 1}": value for i, value in enumerate(row)}
            for row in self.as_rows()
        ]

    def as_dict(self) -> dict[str, str]:
        """``key: value`` pairs from the body, over any non-protocol headers."""
        result = {k: v for k, v in self.headers.items() if k.lower() not in _PROTOCOL_HEADERS}
        for line in self.body.splitlines():
            key, sep, value = line.partition(":")
            if sep:
                result[key.strip()] = value.strip()
        return result
