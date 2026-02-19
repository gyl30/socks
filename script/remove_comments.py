#!/usr/bin/env python3
"""
Remove all C/C++ comments from source files using libclang tokens.

By default, rewrites tracked .h/.cpp files (excluding third/ and build/).
Use --check to list files that would change without writing.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

try:
    from clang import cindex
except Exception as exc:
    print(f"failed to import libclang: {exc}", file=sys.stderr)
    sys.exit(1)


EXCLUDE_BASENAMES = {"log.cpp", "log.h", "reflect.h"}


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def git_tracked_files(root: Path) -> List[Path]:
    result = subprocess.run(
        ["git", "ls-files", "*.h", "*.cpp"],
        cwd=str(root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    return [root / p for p in result.stdout.splitlines() if p]


def collect_files(root: Path, paths: List[str]) -> List[Path]:
    if paths:
        files = [root / p for p in paths]
    else:
        files = git_tracked_files(root)

    filtered: List[Path] = []
    for p in files:
        rel = p.relative_to(root)
        if p.name in EXCLUDE_BASENAMES:
            continue
        if str(rel).startswith("third/"):
            continue
        if str(rel).startswith("build/") or str(rel).startswith("build_"):
            continue
        if str(rel).startswith("Testing/"):
            continue
        if not p.exists() or p.suffix not in (".h", ".cpp"):
            continue
        filtered.append(p)
    return filtered


def build_clang_args(root: Path) -> List[str]:
    return [
        "-x",
        "c++",
        "-std=c++23",
        f"-I{root}",
        f"-I{root / 'third' / 'spdlog' / 'include'}",
        f"-I{root / 'third' / 'rapidjson' / 'include'}",
    ]


def line_starts(text: str) -> List[int]:
    starts = [0]
    for idx, ch in enumerate(text):
        if ch == "\n":
            starts.append(idx + 1)
    return starts


def to_offset(starts: List[int], line: int, col: int) -> int:
    if line <= 0:
        return 0
    if line > len(starts):
        return starts[-1]
    return starts[line - 1] + max(col - 1, 0)


def same_file(path_a: str, path_b: str) -> bool:
    try:
        return os.path.samefile(path_a, path_b)
    except Exception:
        return os.path.abspath(path_a) == os.path.abspath(path_b)


def comment_ranges(path: Path, code: str, clang_args: List[str]) -> Optional[List[Tuple[int, int]]]:
    index = cindex.Index.create()
    options = (
        cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
        | cindex.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES
    )
    try:
        tu = index.parse(str(path), args=clang_args, options=options)
    except Exception:
        print(f"failed to parse {path}", file=sys.stderr)
        return None

    starts = line_starts(code)
    ranges: List[Tuple[int, int]] = []
    for token in tu.get_tokens(extent=tu.cursor.extent):
        if token.kind != cindex.TokenKind.COMMENT:
            continue
        loc = token.location
        if not loc.file or not same_file(loc.file.name, str(path)):
            continue
        start = token.extent.start
        end = token.extent.end
        start_offset = to_offset(starts, start.line, start.column)
        end_offset = to_offset(starts, end.line, end.column)
        if end_offset <= start_offset:
            continue
        ranges.append((start_offset, end_offset))
    ranges.sort()
    # merge overlaps
    merged: List[Tuple[int, int]] = []
    for s, e in ranges:
        if not merged or s > merged[-1][1]:
            merged.append((s, e))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
    return merged


def strip_comments(code: str, ranges: List[Tuple[int, int]]) -> str:
    if not ranges:
        return code
    chars = list(code)
    for s, e in ranges:
        for i in range(s, min(e, len(chars))):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


def main() -> int:
    parser = argparse.ArgumentParser(description="Remove all comments from C/C++ sources.")
    parser.add_argument("--check", action="store_true", help="only report files that would change")
    parser.add_argument("files", nargs="*", help="optional file list; default is tracked .h/.cpp")
    args = parser.parse_args()

    root = repo_root()
    files = collect_files(root, args.files)
    if not files:
        print("no files to process", file=sys.stderr)
        return 1

    clang_args = build_clang_args(root)
    changed = []
    failures = 0
    for path in files:
        text = path.read_text(encoding="utf-8")
        ranges = comment_ranges(path, text, clang_args)
        if ranges is None:
            failures += 1
            continue
        stripped = strip_comments(text, ranges)
        if stripped != text:
            changed.append(str(path.relative_to(root)))
            if not args.check:
                path.write_text(stripped, encoding="utf-8")

    if failures:
        print(f"failed to parse {failures} file(s)", file=sys.stderr)
        return 2
    if changed:
        print("\n".join(changed))
        if args.check:
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
