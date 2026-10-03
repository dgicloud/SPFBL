#!/usr/bin/env python3
"""Compatibility entry point for the shared SPFBL envelope client."""

import os
import sys

CLIENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODULE_DIRS = (
    CLIENT_DIR,
    os.path.join(CLIENT_DIR, "common"),
    os.path.abspath(os.path.join(CLIENT_DIR, "..", "common")),
)
for module_dir in MODULE_DIRS:
    if os.path.isfile(os.path.join(module_dir, "spfbl_client.py")):
        if module_dir not in sys.path:
            sys.path.insert(0, module_dir)
        break

from spfbl_client import *  # noqa: F401,F403,E402


if __name__ == "__main__":
    raise SystemExit(main())
