#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2026 Alexander D. Kanevskiy <kad@blackcatlinux.com>

"""Entry point for setups that call ``joker.py`` directly, such as lego's exec provider.

Requires the package to be installed (``pip install .``).
"""

import sys

from joker_dmapi.cli import main

if __name__ == "__main__":
    sys.exit(main())
