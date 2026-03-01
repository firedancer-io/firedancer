#!/usr/bin/env python3
"""Overwrite every file under a shared-memory directory with random or zero bytes."""

from __future__ import annotations

import argparse
import mmap
import os
import sys

ALLOWED_FS_TYPES = {"hugetlbfs", "tmpfs"}

CHUNK = 64 * 1024 * 1024  # 64 MiB


def _read_mounts() -> list[tuple[str, str]]:
    """Return list of (mountpoint, fstype) from /proc/mounts."""
    mounts = []
    with open("/proc/mounts") as f:
        for line in f:
            parts = line.split()
            # format: device mountpoint fstype options ...
            mounts.append((parts[1], parts[2]))
    return mounts


def _find_mount(filepath: str, mounts: list[tuple[str, str]]) -> tuple[str, str] | None:
    """Find the longest-prefix mount for filepath."""
    filepath = os.path.realpath(filepath)
    best: tuple[str, str] | None = None
    for mountpoint, fstype in mounts:
        if filepath == mountpoint or filepath.startswith(mountpoint + "/"):
            if best is None or len(mountpoint) > len(best[0]):
                best = (mountpoint, fstype)
    return best


def smash(path: str, dry_run: bool = False, zero: bool = False) -> None:
    if not os.path.isdir(path):
        print(f"error: {path} does not exist or is not a directory", file=sys.stderr)
        sys.exit(1)

    mounts = _read_mounts()
    fill = b"\x00" * CHUNK if zero else os.urandom(CHUNK)

    for dirpath, _, filenames in os.walk(path):
        for name in filenames:
            filepath = os.path.join(dirpath, name)
            try:
                file_mount = _find_mount(filepath, mounts)
                if file_mount is None or file_mount[1] not in ALLOWED_FS_TYPES:
                    fs_info = (
                        f"on {file_mount[1]} (mount {file_mount[0]})"
                        if file_mount
                        else "not on any known mount"
                    )
                    print(
                        f"skipping {filepath}: {fs_info}, "
                        f"not in {ALLOWED_FS_TYPES}",
                        file=sys.stderr,
                    )
                    continue

                size = os.path.getsize(filepath)
                if size == 0:
                    continue
                if dry_run:
                    print(f"would smash {filepath} ({size} bytes)")
                    continue
                with open(filepath, "r+b") as f:
                    with mmap.mmap(f.fileno(), size) as mm:
                        offset = 0
                        while offset < size:
                            n = min(CHUNK, size - offset)
                            mm[offset:offset + n] = fill[:n]
                            offset += n
                print(f"smashed {filepath} ({size} bytes)")
            except OSError as e:
                print(f"skipping {filepath}: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Overwrite every file in a directory tree with random or zero bytes "
        "without changing file sizes."
    )
    parser.add_argument(
        "--shmem-path",
        default="/mnt/.fd",
        help="root directory to smash (default: /mnt/.fd)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print files that would be smashed without writing",
    )
    parser.add_argument(
        "--zero",
        action="store_true",
        help="fill with zeros instead of random bytes",
    )
    args = parser.parse_args()
    try:
        smash(args.shmem_path, dry_run=args.dry_run, zero=args.zero)
    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == "__main__":
    main()
