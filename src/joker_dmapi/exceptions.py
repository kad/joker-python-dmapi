# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

"""Exceptions raised by the Joker DMAPI client."""

from __future__ import annotations


class JokerError(Exception):
    """Base class for all errors raised by this package."""


class JokerConnectionError(JokerError):
    """The HTTP request failed or returned a non-200 status."""


class JokerAPIError(JokerError):
    """DMAPI answered with a Status-Code outside the success range (0 and 1000-1999)."""

    def __init__(self, code: int, text: str, headers: dict[str, str] | None = None) -> None:
        """Store the DMAPI status code, text and the raw response headers."""
        super().__init__(f"DMAPI error {code}: {text}")
        self.code = code
        self.text = text
        self.headers = headers or {}


class JokerAuthError(JokerAPIError):
    """Login failed."""
