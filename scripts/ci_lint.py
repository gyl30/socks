#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys


def build_safe_git_env(repo_root):
    env = os.environ.copy()
    count_text = env.get("GIT_CONFIG_COUNT", "0")
    try:
        count = int(count_text)
    except ValueError:
        count = 0
    env[f"GIT_CONFIG_KEY_{count}"] = "safe.directory"
    env[f"GIT_CONFIG_VALUE_{count}"] = str(pathlib.Path(repo_root).resolve())
    env["GIT_CONFIG_COUNT"] = str(count + 1)
    return env


def run_checked(args, cwd, capture_output=False):
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=capture_output, env=build_safe_git_env(cwd))
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


def pick_clang_tidy():
    candidates = [
        "clang-tidy-23",
        "clang-tidy-22",
        "clang-tidy-21",
        "clang-tidy-20",
        "clang-tidy-19",
        "clang-tidy-18",
        "clang-tidy",
    ]
    for candidate in candidates:
        path = shutil.which(candidate)
        if path is not None:
            return path
    raise RuntimeError("missing clang-tidy")


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
    probe = subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo_root, text=True, env=build_safe_git_env(repo_root))
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
    abs_path = str((repo_root / rel_path).resolve())
    return json.dumps([{"name": abs_path, "lines": ranges}])


def run_git_clang_format(repo_root, base_sha, files):
    git_clang_format = pick_git_clang_format()
    args = [git_clang_format, "--binary=clang-format", base_sha, "--diff", "--", *files]
    run_checked(args, repo_root)


def collect_compile_db_include_args(repo_root, build_dir):
    compile_commands_path = repo_root / build_dir / "compile_commands.json"
    if not compile_commands_path.is_file():
        return []

    try:
        entries = json.loads(compile_commands_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    include_args = []
    seen = set()
    for entry in entries:
        command = entry.get("command", "")
        if not command:
            continue

        try:
            parts = shlex.split(command)
        except ValueError:
            continue

        idx = 0
        while idx < len(parts):
            part = parts[idx]
            include_arg = None
            if part == "-I" or part == "-isystem":
                if idx + 1 < len(parts):
                    include_arg = f"{part}{parts[idx + 1]}"
                    idx += 1
            elif part.startswith("-I") or part.startswith("-isystem"):
                include_arg = part

            if include_arg is not None and include_arg not in seen:
                seen.add(include_arg)
                include_args.append(f"--extra-arg-before={include_arg}")
            idx += 1

    return include_args


def run_clang_tidy(repo_root, base_sha, head_sha, files, build_dir):
    clang_tidy = pick_clang_tidy()

    repo_root_str = str(repo_root)
    extra_args = [
        f"--extra-arg-before=-I{repo_root_str}",
        f"--extra-arg-before=-I{repo_root_str}/third/rapidjson/include",
        f"--extra-arg-before=-I{repo_root_str}/third/spdlog/include",
        *collect_compile_db_include_args(repo_root, build_dir),
        "--extra-arg=-std=c++23",
        "-warnings-as-errors=*",
    ]

    for rel_path in files:
        if not rel_path.endswith((".cpp", ".cc", ".cxx")):
            continue
        line_filter = build_line_filter(repo_root, base_sha, head_sha, rel_path)
        if line_filter is None:
            continue
        abs_path = str((repo_root / rel_path).resolve())
        run_checked([clang_tidy, "-p", build_dir, *extra_args, f"-line-filter={line_filter}", abs_path], repo_root)


def main():
    parser = argparse.ArgumentParser(description="Run diff-scoped clang-format and clang-tidy checks")
    parser.add_argument("--base-sha", default="")
    parser.add_argument("--head-sha", default="HEAD")
    parser.add_argument("--build-dir", default="build")
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

    run_clang_tidy(repo_root, base_sha, head_sha, files, args.build_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
