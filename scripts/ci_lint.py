#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys


def run_checked(args, cwd, capture_output=False):
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=capture_output)
    if result.returncode != 0:
        stdout = result.stdout if result.stdout is not None else ""
        stderr = result.stderr if result.stderr is not None else ""
        raise RuntimeError(f"command failed: {' '.join(args)}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    return result


def pick_git_clang_format():
    candidates = [
        "git-clang-format",
        "git-clang-format-23",
        "git-clang-format-20",
        "git-clang-format-18",
        "git-clang-format-16",
        "git-clang-format-15",
        "git-clang-format-14",
        "git-clang-format-11",
    ]
    for candidate in candidates:
        path = shutil.which(candidate)
        if path is not None:
            return path
    raise RuntimeError("missing git-clang-format")


def resolve_base_sha(repo_root, base_sha):
    if base_sha:
        return base_sha

    git_base = os.environ.get("CI_BASE_SHA", "")
    if git_base:
        return git_base

    try:
        return run_checked(["git", "rev-parse", "HEAD^"], repo_root, capture_output=True).stdout.strip()
    except RuntimeError:
        return run_checked(["git", "rev-parse", "HEAD"], repo_root, capture_output=True).stdout.strip()


def ensure_commit_available(repo_root, sha):
    if not sha:
        return
    probe = subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo_root, text=True)
    if probe.returncode == 0:
        return
    run_checked(["git", "fetch", "--depth=1", "origin", sha], repo_root)


def list_changed_files(repo_root, base_sha, head_sha):
    result = run_checked(
        ["git", "diff", "--name-only", base_sha, head_sha, "--", "*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp"],
        repo_root,
        capture_output=True,
    )
    files = []
    for line in result.stdout.splitlines():
        if not line:
            continue
        if line.startswith("third/") or line.startswith("build/") or line.startswith("fuzz/"):
            continue
        files.append(line)
    return files


def build_line_filter(repo_root, base_sha, head_sha, rel_path):
    diff = run_checked(["git", "diff", "--unified=0", base_sha, head_sha, "--", rel_path], repo_root, capture_output=True).stdout
    ranges = []
    for line in diff.splitlines():
        match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
        if match is None:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or "1")
        if count > 0:
            ranges.append([start, start + count - 1])
    if not ranges:
        return None
    return json.dumps([{ "name": rel_path, "lines": ranges }])


def run_git_clang_format(repo_root, base_sha, files):
    git_clang_format = pick_git_clang_format()
    args = [git_clang_format, "--binary=clang-format", base_sha, "--diff", "--", *files]
    run_checked(args, repo_root)


def run_clang_tidy(repo_root, base_sha, head_sha, files):
    clang_tidy = shutil.which("clang-tidy")
    if clang_tidy is None:
        raise RuntimeError("missing clang-tidy")

    repo_root_str = str(repo_root)
    extra_args = [
        f"--extra-arg-before=-I{repo_root_str}/third/rapidjson/include",
        f"--extra-arg-before=-I{repo_root_str}/third/spdlog/include",
        "--extra-arg=-std=c++23",
        "-warnings-as-errors=*",
    ]

    for rel_path in files:
        if not rel_path.endswith((".cpp", ".cc", ".cxx")):
            continue
        line_filter = build_line_filter(repo_root, base_sha, head_sha, rel_path)
        if line_filter is None:
            continue
        run_checked([clang_tidy, "-p", "build", *extra_args, f"-line-filter={line_filter}", rel_path, "--"], repo_root)


def main():
    parser = argparse.ArgumentParser(description="Run diff-scoped clang-format and clang-tidy checks")
    parser.add_argument("--base-sha", default="")
    parser.add_argument("--head-sha", default="HEAD")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    base_sha = resolve_base_sha(repo_root, args.base_sha)
    head_sha = args.head_sha
    ensure_commit_available(repo_root, base_sha)

    files = list_changed_files(repo_root, base_sha, head_sha)
    if not files:
        print(f"no changed source files between {base_sha} and {head_sha}")
        return 0

    format_files = [path for path in files if path.endswith((".cpp", ".cc", ".cxx", ".h", ".hpp"))]
    if format_files:
        run_git_clang_format(repo_root, base_sha, format_files)

    run_clang_tidy(repo_root, base_sha, head_sha, files)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
