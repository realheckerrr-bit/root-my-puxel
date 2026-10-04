#!/usr/bin/env python3
"""Extract only boot.img from Google's nested Pixel factory ZIPs.

Factory archives are several gigabytes and contain a large system image.  The
boot image is a small ZIP member, so this downloader uses HTTP range requests
to read the two ZIP central directories and the compressed boot.img member.
It never downloads or stores the rest of the factory image.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import urllib.request
import zlib
from pathlib import Path


EOCD = b"PK\x05\x06"
CENTRAL = b"PK\x01\x02"
LOCAL = b"PK\x03\x04"


def request(url: str, start: int, end: int) -> bytes:
    req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
    with urllib.request.urlopen(req) as response:
        data = response.read()
        if response.status != 206:
            raise RuntimeError(f"{url} did not honor range request ({response.status})")
        expected = end - start + 1
        if len(data) != expected:
            raise RuntimeError(f"short range for {url}: got {len(data)}, expected {expected}")
        return data


def remote_size(url: str) -> int:
    # Google occasionally serves a stale Content-Length for HEAD while the
    # ranged response carries the current archive size.  Use Content-Range
    # from a one-byte request so ZIP offsets always refer to the same object.
    req = urllib.request.Request(url, headers={"Range": "bytes=0-0"})
    with urllib.request.urlopen(req) as response:
        content_range = response.headers.get("Content-Range", "")
        match = re.fullmatch(r"bytes 0-0/(\d+)", content_range)
        if not match:
            raise RuntimeError(f"no usable Content-Range for {url}: {content_range!r}")
        if response.status != 206 or len(response.read()) != 1:
            raise RuntimeError(f"range probe failed for {url}")
        return int(match.group(1))


def central_directory(url: str, archive_start: int, archive_size: int) -> list[dict[str, int | str]]:
    window = min(65557, archive_size)
    tail = request(url, archive_start + archive_size - window, archive_start + archive_size - 1)
    eocd_at = tail.rfind(EOCD)
    if eocd_at < 0:
        raise RuntimeError(f"ZIP end record not found in {url}")
    eocd = tail[eocd_at : eocd_at + 22]
    _, disk, cd_disk, disk_entries, entries, cd_size, cd_offset, comment_size = struct.unpack(
        "<4s4H2IH", eocd
    )
    if disk or cd_disk or disk_entries != entries:
        raise RuntimeError("multi-disk ZIP is not supported")
    if cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
        raise RuntimeError("ZIP64 central directories are not supported")
    central = request(
        url,
        archive_start + cd_offset,
        archive_start + cd_offset + cd_size - 1,
    )
    result: list[dict[str, int | str]] = []
    pos = 0
    for _ in range(entries):
        if central[pos : pos + 4] != CENTRAL:
            raise RuntimeError(f"invalid central directory at offset {pos:#x}")
        fields = struct.unpack("<4s6H3I5H2I", central[pos : pos + 46])
        _, _, _, flags, method, _, _, crc, compressed, uncompressed, name_len, extra_len, comment_len, _, _, _, local_offset = fields
        name_start = pos + 46
        name = central[name_start : name_start + name_len].decode("utf-8", "replace")
        result.append(
            {
                "name": name,
                "method": method,
                "flags": flags,
                "crc": crc,
                "compressed": compressed,
                "uncompressed": uncompressed,
                "local_offset": local_offset,
            }
        )
        pos += 46 + name_len + extra_len + comment_len
    return result


def member_bytes(url: str, archive_start: int, member: dict[str, int | str]) -> bytes:
    local_offset = int(member["local_offset"])
    local = request(url, archive_start + local_offset, archive_start + local_offset + 29)
    if local[:4] != LOCAL:
        raise RuntimeError(f"invalid local header for {member['name']}")
    name_len, extra_len = struct.unpack_from("<2H", local, 26)
    data_start = archive_start + local_offset + 30 + name_len + extra_len
    compressed = int(member["compressed"])
    data = request(url, data_start, data_start + compressed - 1)
    if int(member["method"]) == 0:
        result = data
    elif int(member["method"]) == 8:
        result = zlib.decompress(data, -15)
    else:
        raise RuntimeError(f"unsupported ZIP method {member['method']} for {member['name']}")
    if len(result) != int(member["uncompressed"]):
        raise RuntimeError(f"size mismatch for {member['name']}")
    if (zlib.crc32(result) & 0xFFFFFFFF) != int(member["crc"]):
        raise RuntimeError(f"CRC mismatch for {member['name']}")
    return result


def extract_boot(url: str) -> bytes:
    outer_size = remote_size(url)
    outer_entries = central_directory(url, 0, outer_size)
    image = next(
        (
            entry
            for entry in outer_entries
            if str(entry["name"]).startswith("image-") and str(entry["name"]).endswith(".zip")
        ),
        None,
    )
    if image is None:
        raise RuntimeError(f"nested image ZIP not found in {url}")
    inner_offset = int(image["local_offset"])
    local = request(url, inner_offset, inner_offset + 29)
    name_len, extra_len = struct.unpack_from("<2H", local, 26)
    inner_start = inner_offset + 30 + name_len + extra_len
    inner_entries = central_directory(url, inner_start, int(image["uncompressed"]))
    boot = next((entry for entry in inner_entries if entry["name"] == "boot.img"), None)
    if boot is None:
        raise RuntimeError(f"boot.img not found in {url}")
    return member_bytes(url, inner_start, boot)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--build", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    build = manifest["builds"][args.build]
    args.out.mkdir(parents=True, exist_ok=True)
    for codename, filename in build["images"]:
        url = f"{build['imageBase'].rstrip('/')}/{filename}"
        print(f"[*] {codename}: reading {url}", flush=True)
        boot = extract_boot(url)
        digest = hashlib.sha256(boot).hexdigest()
        destination = args.out / f"{codename}.boot.img"
        destination.write_bytes(boot)
        print(f"[+] {codename}: {len(boot)} bytes sha256={digest}", flush=True)


if __name__ == "__main__":
    main()
