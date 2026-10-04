#!/usr/bin/env python3
"""Print the display string for one official build manifest entry."""

from __future__ import annotations

import json
import sys
from pathlib import Path


manifest_path, build = Path(sys.argv[1]), sys.argv[2]
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
print(manifest["builds"][build]["display"])
