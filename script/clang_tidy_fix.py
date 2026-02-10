#!/usr/bin/env python3
"""
Run clang-tidy and apply fixes for selected checks.

Example:
  python3 script/clang_tidy_fix.py --checks "modernize-*,performance-*"
  python3 script/clang_tidy_fix.py --checks "bugprone-*,-bugprone-easily-swappable-parameters" --jobs 4
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, List


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
        if p.name in EXCLUDE_BASENAMES:
            continue
        rel = p.relative_to(root)
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


def find_clang_tidy(path: str | None) -> str:
    if path:
        return path
    found = shutil.which("clang-tidy")
    if not found:
        raise RuntimeError("clang-tidy not found in PATH")
    return found


def run_clang_tidy(
    clang_tidy: str,
    file_path: Path,
    build_dir: Path,
    checks: str | None,
    apply_fixes: bool,
    extra_args: List[str],
    extra_args_before: List[str],
) -> int:
    cmd = [clang_tidy, str(file_path), "-p", str(build_dir)]
    if checks:
        cmd.append(f"-checks={checks}")
    if apply_fixes:
        cmd.extend(["-fix", "-format-style=file"])
    for arg in extra_args_before:
        cmd.append(f"--extra-arg-before={arg}")
    for arg in extra_args:
        cmd.append(f"--extra-arg={arg}")
    result = subprocess.run(cmd)
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Run clang-tidy with auto-fix for selected checks.")
    parser.add_argument("--checks", help="clang-tidy checks pattern, e.g. 'modernize-*,performance-*'")
    parser.add_argument("--build-dir", default="build", help="build dir containing compile_commands.json")
    parser.add_argument("--clang-tidy", dest="clang_tidy", help="clang-tidy binary path")
    parser.add_argument("--no-fix", action="store_true", help="only report diagnostics, do not apply fixes")
    parser.add_argument("--jobs", type=int, default=1, help="parallel jobs")
    parser.add_argument("--extra-arg", action="append", default=[], help="extra compiler arg")
    parser.add_argument("--extra-arg-before", action="append", default=[], help="extra compiler arg before")
    parser.add_argument("files", nargs="*", help="optional file list; default is tracked .h/.cpp")
    args = parser.parse_args()

    root = repo_root()
    build_dir = (root / args.build_dir).resolve()
    compile_db = build_dir / "compile_commands.json"
    if not compile_db.exists():
        print(f"compile_commands.json not found: {compile_db}", file=sys.stderr)
        print("hint: cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -S . -B build", file=sys.stderr)
        return 1

    try:
        clang_tidy = find_clang_tidy(args.clang_tidy)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    files = collect_files(root, args.files)
    if not files:
        print("no files to process", file=sys.stderr)
        return 1

    apply_fixes = not args.no_fix
    if apply_fixes and args.jobs > 1:
        print("clang-tidy -fix is not safe with parallel jobs, forcing jobs=1", file=sys.stderr)
        args.jobs = 1
    failures = 0
    if args.jobs <= 1:
        for f in files:
            ret = run_clang_tidy(
                clang_tidy,
                f,
                build_dir,
                args.checks,
                apply_fixes,
                args.extra_arg,
                args.extra_arg_before,
            )
            if ret != 0:
                failures += 1
    else:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = [
                pool.submit(
                    run_clang_tidy,
                    clang_tidy,
                    f,
                    build_dir,
                    args.checks,
                    apply_fixes,
                    args.extra_arg,
                    args.extra_arg_before,
                )
                for f in files
            ]
            for fut in as_completed(futures):
                if fut.result() != 0:
                    failures += 1

    if failures:
        print(f"clang-tidy finished with {failures} failures", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
