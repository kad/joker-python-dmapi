# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

"""Python client for the Joker.com DMAPI."""

from importlib.metadata import PackageNotFoundError, version

from .client import Joker, Zone, split_fqdn
from .exceptions import (
    JokerAPIError,
    JokerAuthError,
    JokerConnectionError,
    JokerError,
)
from .response import JokerResponse, Status

try:
    __version__ = version("joker-dmapi")
except PackageNotFoundError:  # not installed
    __version__ = "0+unknown"

__all__ = [
    "Joker",
    "JokerAPIError",
    "JokerAuthError",
    "JokerConnectionError",
    "JokerError",
    "JokerResponse",
    "Status",
    "Zone",
    "__version__",
    "split_fqdn",
]
