#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


CPP_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
LIZARD_PREFIX_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+(.+)$")
LIZARD_LOCATION_RE = re.compile(r"@(\d+)-(\d+)@(.+)$")


@dataclass(frozen=True)
class FunctionMetric:
    file: str
    start_line: int
    end_line: int
    ccn: int
    name: str


def run_command(cmd: list[str], cwd: Path, allow_failure: bool = False) -> str:
    result = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    if result.returncode != 0 and not allow_failure:
        command = " ".join(cmd)
        raise RuntimeError(f"command failed ({command}): {result.stderr.strip()}")
    return result.stdout


def git_ref_exists(repo_root: Path, ref: str) -> bool:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", f"{ref}^{{commit}}"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def resolve_base_ref(repo_root: Path, preferred_base: str) -> str:
    candidates = [preferred_base]
    if preferred_base.startswith("origin/"):
        candidates.append(preferred_base.split("/", 1)[1])
    candidates.extend(["origin/main", "main", "origin/master", "master", "HEAD~1"])
    seen: set[str] = set()
    for ref in candidates:
        if ref in seen:
            continue
        seen.add(ref)
        if git_ref_exists(repo_root, ref):
            return ref
    return "HEAD"


def resolve_base_commit(repo_root: Path, base_ref: str) -> str:
    merge_base = run_command(["git", "merge-base", base_ref, "HEAD"], repo_root, allow_failure=True).strip()
    if merge_base:
        return merge_base
    return run_command(["git", "rev-parse", base_ref], repo_root).strip()


def list_changed_cpp_files(repo_root: Path, base_commit: str) -> list[str]:
    output = run_command(["git", "diff", "--name-only", "--diff-filter=AMR", f"{base_commit}..HEAD"], repo_root)
    files: list[str] = []
    for line in output.splitlines():
        path = line.strip()
        if not path:
            continue
        suffix = Path(path).suffix.lower()
        if suffix in CPP_EXTENSIONS:
            files.append(path)
    return files


def changed_line_ranges(repo_root: Path, base_commit: str, file_path: str) -> list[tuple[int, int]]:
    patch = run_command(["git", "diff", "--unified=0", "--no-color", f"{base_commit}..HEAD", "--", file_path], repo_root)
    ranges: list[tuple[int, int]] = []
    for line in patch.splitlines():
        match = HUNK_RE.match(line)
        if not match:
            continue
        start = int(match.group(1))
        length = int(match.group(2) or "1")
        if length == 0:
            continue
        ranges.append((start, start + length - 1))
    return ranges


def parse_lizard_output(output: str) -> list[FunctionMetric]:
    functions: list[FunctionMetric] = []
    for line in output.splitlines():
        prefix_match = LIZARD_PREFIX_RE.match(line)
        if not prefix_match:
            continue
        ccn = int(prefix_match.group(2))
        function_with_location = prefix_match.group(3).strip()
        location_match = LIZARD_LOCATION_RE.search(function_with_location)
        if not location_match:
            continue
        start_line = int(location_match.group(1))
        end_line = int(location_match.group(2))
        file_path = Path(location_match.group(3).strip()).as_posix()
        name = function_with_location[: location_match.start()].strip()
        functions.append(
            FunctionMetric(
                file=file_path,
                start_line=start_line,
                end_line=end_line,
                ccn=ccn,
                name=name,
            )
        )
    return functions


def overlaps_changed_lines(metric: FunctionMetric, ranges: list[tuple[int, int]]) -> bool:
    for start, end in ranges:
        if metric.start_line <= end and metric.end_line >= start:
            return True
    return False


def run_complexity_gate(repo_root: Path, base_ref: str, threshold: int) -> int:
    resolved_base_ref = resolve_base_ref(repo_root, base_ref)
    base_commit = resolve_base_commit(repo_root, resolved_base_ref)
    files = list_changed_cpp_files(repo_root, base_commit)
    if not files:
        print(f"[complexity] no changed C/C++ files since {base_commit}; skip")
        return 0

    changed_ranges: dict[str, list[tuple[int, int]]] = {}
    for file_path in files:
        changed_ranges[Path(file_path).as_posix()] = changed_line_ranges(repo_root, base_commit, file_path)

    lizard_cmd = [sys.executable, "-m", "lizard", *files]
    try:
        lizard_output = run_command(lizard_cmd, repo_root)
    except RuntimeError as exc:
        print(f"[complexity] failed to run lizard: {exc}", file=sys.stderr)
        print("[complexity] install dependency: python3 -m pip install lizard", file=sys.stderr)
        return 2

    functions = parse_lizard_output(lizard_output)
    considered = 0
    violations: list[FunctionMetric] = []
    for metric in functions:
        metric_file = Path(metric.file).as_posix()
        ranges = changed_ranges.get(metric_file, [])
        if not ranges:
            continue
        if not overlaps_changed_lines(metric, ranges):
            continue
        considered += 1
        if metric.ccn > threshold:
            violations.append(metric)

    print(
        f"[complexity] base_ref={resolved_base_ref} base_commit={base_commit} "
        f"changed_files={len(files)} changed_functions={considered} threshold={threshold}"
    )
    if not violations:
        print("[complexity] pass")
        return 0

    print("[complexity] fail: changed function complexity exceeds threshold")
    for metric in violations:
        print(
            f"  - {metric.file}:{metric.start_line}-{metric.end_line} "
            f"CCN={metric.ccn} > {threshold} :: {metric.name}"
        )
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Gate cyclomatic complexity for changed C/C++ functions.")
    parser.add_argument("--base", default="origin/main", help="Git base ref/sha used to compute changed lines.")
    parser.add_argument("--threshold", type=int, default=15, help="Cyclomatic complexity threshold for changed functions.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    return run_complexity_gate(repo_root=repo_root, base_ref=args.base, threshold=args.threshold)


if __name__ == "__main__":
    raise SystemExit(main())
