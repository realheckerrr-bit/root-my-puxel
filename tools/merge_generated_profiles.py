#!/usr/bin/env python3
"""Add generated official targets to the APK profile catalog."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--profiles", type=Path, required=True)
    args = parser.parse_args()

    generated = json.loads(args.generated.read_text(encoding="utf-8"))
    catalog = json.loads(args.profiles.read_text(encoding="utf-8"))
    profiles = catalog["profiles"]
    by_id = {profile["profileId"]: profile for profile in profiles}
    for profile_id, record in generated.items():
        by_id[profile_id] = {
            "profileId": profile_id,
            "codename": record["codename"],
            "kernelRelease": record["kernelReleasePrefix"],
            "buildDisplay": record["buildDisplay"],
            "exploitAsset": f"exploits/{profile_id}.so",
            "kmi": record["kmi"],
        }
    catalog["profiles"] = list(by_id.values())
    args.profiles.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    print(f"catalog now contains {len(catalog['profiles'])} profiles")


if __name__ == "__main__":
    main()
