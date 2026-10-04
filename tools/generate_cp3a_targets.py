#!/usr/bin/env python3
"""Generate exact target headers from official Pixel boot images.

The factory archives are intentionally not checked into the repository.  This
tool consumes boot.img files extracted from those archives, resolves kallsyms
with kallsyms-finder, and writes the small per-device target headers used by
the native payload build.
"""

from __future__ import annotations

import argparse
import gc
import json
import re
import subprocess
from pathlib import Path


FAMILY_BASE = {
    61: 0xFFFFFFC008000000,
    66: 0xFFFFFFC080000000,
}

TEMPLATE_BUILD = {
    "akita": "akita-CP2A.260805.005",
    "stallion": "stallion-CP2A.260805.005",
    "felix": "felix-CP2A.260605.012",
}


def u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def decode_lz4_block(src: bytes) -> bytes:
    pos = 0
    out = bytearray()
    while pos < len(src):
        token = src[pos]
        pos += 1
        literal_len = token >> 4
        if literal_len == 15:
            while True:
                extra = src[pos]
                pos += 1
                literal_len += extra
                if extra != 255:
                    break
        out.extend(src[pos : pos + literal_len])
        pos += literal_len
        if pos >= len(src):
            break
        match_offset = src[pos] | (src[pos + 1] << 8)
        pos += 2
        if not match_offset or match_offset > len(out):
            raise ValueError(f"invalid LZ4 match offset: {match_offset:#x}")
        match_len = (token & 0xF) + 4
        if (token & 0xF) == 15:
            while True:
                extra = src[pos]
                pos += 1
                match_len += extra
                if extra != 255:
                    break
        for _ in range(match_len):
            out.append(out[-match_offset])
    return bytes(out)


def decompress_legacy_lz4(data: bytes) -> bytes:
    # Android's legacy LZ4 stream magic is 02 21 4c 18.
    if data[:4] != bytes.fromhex("02214c18"):
        return data
    pos = 4
    output = bytearray()
    while pos + 4 <= len(data):
        block_size = u32(data, pos)
        pos += 4
        if block_size == 0:
            break
        uncompressed = bool(block_size & 0x80000000)
        block_size &= 0x7FFFFFFF
        block = data[pos : pos + block_size]
        pos += block_size
        if len(block) != block_size:
            raise ValueError("truncated legacy LZ4 block")
        output.extend(block if uncompressed else decode_lz4_block(block))
    return bytes(output)


def extract_kernel(boot_image: bytes) -> bytes:
    if boot_image[:8] != b"ANDROID!":
        raise ValueError("not an Android boot image")
    kernel_size = u32(boot_image, 8)
    # CP3A images use the 4 KiB kernel offset used by boot header v3/v4.
    return decompress_legacy_lz4(boot_image[4096 : 4096 + kernel_size])


def resolve_symbols(kernel_path: Path, finder: str) -> tuple[str, int, dict[str, int]]:
    kernel = kernel_path.read_bytes()
    release_match = re.search(rb"Linux version ([^ ]+)", kernel)
    if not release_match:
        raise ValueError(f"kernel release not found in {kernel_path.name}")
    release = release_match.group(1).decode("ascii", "replace")
    family = 66 if "6.6" in release else 61 if "6.1" in release else 0
    if not family:
        raise ValueError(f"unsupported kernel family in {release}")

    result = subprocess.run(
        [finder, str(kernel_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    absolute: dict[str, int] = {}
    # kallsyms-finder prints its diagnostics and resolved table to stderr.
    for line in (result.stdout + "\n" + result.stderr).splitlines():
        fields = line.split()
        if len(fields) >= 3 and re.fullmatch(r"[0-9a-fA-F]+", fields[0]):
            absolute[fields[2]] = int(fields[0], 16)
    base = FAMILY_BASE[family]
    offsets = {name: value - base for name, value in absolute.items() if value >= base}
    return release, family, offsets


def value(symbols: dict[str, int], *names: str) -> int:
    for name in names:
        if symbols.get(name, 0):
            return symbols[name]
    raise KeyError(f"missing symbols: {', '.join(names)}")


def target_header(codename: str, target: str, build_display: str, release: str, family: int, symbols: dict[str, int], template: str) -> str:
    ioctl = value(symbols, "ashmem_ioctl")
    open_ = value(symbols, "ashmem_open")
    if symbols.get("ashmem_fops", 0):
        fops = symbols["ashmem_fops"]
    else:
        fops = ioctl + (0x647E28 if family == 61 else 0x669BB8)
    if symbols.get("ashmem_misc_fops", 0):
        misc_fops = symbols["ashmem_misc_fops"]
    else:
        misc_fops = value(symbols, "ashmem_miscs", "ashmem_misc") + 0x10

    splice = value(symbols, "copy_splice_read", "generic_file_splice_read")
    selinux = value(symbols, "selinux_enforcing", "selinux_state")
    loggers = value(symbols, "loggers") + 0x8
    random_boot_id_data = value(symbols, "random_table") + 0x108

    fields = {
        "ASHMEM_MISC_FOPS_OFF": misc_fops,
        "ASHMEM_FOPS_OFF": fops,
        "ASHMEM_IOCTL_OFF": ioctl,
        "ASHMEM_COMPAT_IOCTL_OFF": value(symbols, "compat_ashmem_ioctl"),
        "ASHMEM_MMAP_OFF": value(symbols, "ashmem_mmap"),
        "ASHMEM_OPEN_OFF": open_,
        "ASHMEM_RELEASE_OFF": value(symbols, "ashmem_release"),
        "ASHMEM_SHOW_FDINFO_OFF": value(symbols, "ashmem_show_fdinfo"),
        "CONFIGFS_READ_ITER_OFF": value(symbols, "configfs_read_iter"),
        "CONFIGFS_BIN_WRITE_ITER_OFF": value(symbols, "configfs_bin_write_iter"),
        "COPY_SPLICE_READ_OFF": splice,
        "NOOP_LLSEEK_OFF": value(symbols, "noop_llseek"),
        "INIT_TASK_OFF": value(symbols, "init_task"),
        "ROOT_TASK_GROUP_OFF": value(symbols, "root_task_group"),
        "SELINUX_ENFORCING_OFF": selinux,
        "SELINUX_BLOB_SIZES_OFF": value(symbols, "selinux_blob_sizes"),
        "SECURITY_HOOK_HEADS_OFF": value(symbols, "security_hook_heads"),
        "KMALLOC_CACHES_OFF": value(symbols, "kmalloc_caches"),
        "ANON_PIPE_BUF_OPS_OFF": value(symbols, "anon_pipe_buf_ops"),
        "CALL_USERMODEHELPER_EXEC_WORK_OFF": value(symbols, "call_usermodehelper_exec_work"),
        "SYSTEM_UNBOUND_WQ_OFF": value(symbols, "system_unbound_wq"),
        "SLIDE_NFULNL_LOGGER_OFF": value(symbols, "nfulnl_logger"),
        "SLIDE_LOGGERS_0_1_OFF": loggers,
        "SLIDE_RANDOM_BOOT_ID_DATA_OFF": random_boot_id_data,
        "SLIDE_SYSCTL_BOOTID_OFF": value(symbols, "sysctl_bootid"),
    }

    lines = [
        f"/* Pixel target {codename}, {build_display}. */",
        f"/* Kernel: {release}; offsets resolved from the official {build_display} boot image. */",
        "",
        f'#include "../{template}/target.h"',
        "",
        "#undef BUILD_VARIANT_LABEL",
        "#if defined(APP_PAYLOAD) && APP_PAYLOAD",
        f'#define BUILD_VARIANT_LABEL "{target}-app"',
        "#else",
        f'#define BUILD_VARIANT_LABEL "{target}-root-umh"',
        "#endif",
        "",
        "#undef BUILD_FINGERPRINT",
        "#define BUILD_FINGERPRINT " + "\\",
        '  "google/' + codename + "/" + codename + ':17/' + build_display + '/generated:user/release-keys"',
        "",
        f"/* Exact {build_display} offsets from KIMAGE_TEXT_BASE. */",
    ]
    ordered = [
        "ASHMEM_MISC_FOPS_OFF", "ASHMEM_FOPS_OFF", "ASHMEM_IOCTL_OFF", "ASHMEM_COMPAT_IOCTL_OFF",
        "ASHMEM_MMAP_OFF", "ASHMEM_OPEN_OFF", "ASHMEM_RELEASE_OFF", "ASHMEM_SHOW_FDINFO_OFF",
        "CONFIGFS_READ_ITER_OFF", "CONFIGFS_BIN_WRITE_ITER_OFF", "COPY_SPLICE_READ_OFF", "NOOP_LLSEEK_OFF",
        "INIT_TASK_OFF", "ROOT_TASK_GROUP_OFF", "SELINUX_ENFORCING_OFF", "SELINUX_BLOB_SIZES_OFF",
        "SECURITY_HOOK_HEADS_OFF", "KMALLOC_CACHES_OFF", "ANON_PIPE_BUF_OPS_OFF",
        "CALL_USERMODEHELPER_EXEC_WORK_OFF", "SYSTEM_UNBOUND_WQ_OFF", "SLIDE_NFULNL_LOGGER_OFF",
        "SLIDE_LOGGERS_0_1_OFF", "SLIDE_RANDOM_BOOT_ID_DATA_OFF", "SLIDE_SYSCTL_BOOTID_OFF",
    ]
    for macro in ordered:
        lines.append(f"#undef {macro}")
        lines.append(f"#define {macro:<36} 0x{fields[macro]:08x}ULL")
    lines.append("#undef SLIDE_INIT_TASK_OFF")
    lines.append("#define SLIDE_INIT_TASK_OFF         INIT_TASK_OFF")
    lines.append("#undef SLIDE_ROOT_TASK_GROUP_OFF")
    lines.append("#define SLIDE_ROOT_TASK_GROUP_OFF   ROOT_TASK_GROUP_OFF")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--boot-cache", type=Path, required=True)
    parser.add_argument("--finder", default="kallsyms-finder")
    parser.add_argument("--build-display", default="CP3A.260905.009")
    parser.add_argument("--output-json", type=Path, default=Path("/tmp/generated-offsets.json"))
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()

    targets_dir = args.repo_root / "Root-My-Pixel-Payloads" / "src" / "targets"
    records: dict[str, dict[str, object]] = {}
    for boot_path in sorted(args.boot_cache.glob("*.boot.img")):
        codename = boot_path.name.removesuffix(".boot.img")
        kernel_path = Path("/tmp") / f"{codename}.{args.build_display}.kernel"
        boot_data = boot_path.read_bytes()
        kernel_data = extract_kernel(boot_data)
        del boot_data
        kernel_path.write_bytes(kernel_data)
        del kernel_data
        release, family, symbols = resolve_symbols(kernel_path, args.finder)
        template = TEMPLATE_BUILD.get(codename, f"{codename}-CP2A.260705.006")
        template_dir = targets_dir / template
        if not template_dir.exists():
            raise FileNotFoundError(f"template missing for {codename}: {template_dir}")
        target = f"{codename}-{args.build_display}"
        (targets_dir / target).mkdir(parents=True, exist_ok=True)
        (targets_dir / target / "target.h").write_text(
            target_header(codename, target, args.build_display, release, family, symbols, template),
            encoding="utf-8",
        )
        records[target] = {
            "codename": codename,
            "kernelRelease": release,
            "kernelReleasePrefix": release.split("-g", 1)[0],
            "buildDisplay": args.build_display,
            "family": family,
            "kmi": "android14-6.1" if family == 61 else "android15-6.6",
            "symbolCount": len(symbols),
        }
        print(f"{target}: {release} family={family} symbols={len(symbols)}")
        del symbols
        gc.collect()
    args.output_json.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(records)} records to {args.output_json}")


if __name__ == "__main__":
    main()
