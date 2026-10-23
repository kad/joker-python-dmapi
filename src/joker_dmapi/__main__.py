# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

"""Allow ``python -m joker_dmapi``."""

import sys

from .cli import main

sys.exit(main())
