#!/usr/bin/env python3
"""
Sort include order using libclang.

Rules (doc/style):
1) Standard library headers
2) Third-party headers
3) extern "C" headers
4) Project headers
Each group sorted by include line length (short to long).
If a C library header must be wrapped by `extern "C"`, keep it in a block.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    from clang import cindex
except Exception as exc:
    print(f"failed to import libclang: {exc}", file=sys.stderr)
    sys.exit(1)


STANDARD_HEADERS = {
    "algorithm",
    "any",
    "array",
    "atomic",
    "bit",
    "bitset",
    "cassert",
    "cctype",
    "cerrno",
    "cfenv",
    "cfloat",
    "charconv",
    "chrono",
    "cinttypes",
    "ciso646",
    "climits",
    "clocale",
    "cmath",
    "codecvt",
    "complex",
    "condition_variable",
    "csetjmp",
    "csignal",
    "cstdarg",
    "cstddef",
    "cstdint",
    "cstdio",
    "cstdlib",
    "cstring",
    "ctgmath",
    "ctime",
    "cuchar",
    "cwchar",
    "cwctype",
    "deque",
    "expected",
    "exception",
    "filesystem",
    "forward_list",
    "fstream",
    "functional",
    "future",
    "initializer_list",
    "iomanip",
    "ios",
    "iosfwd",
    "iostream",
    "istream",
    "iterator",
    "limits",
    "list",
    "locale",
    "map",
    "memory",
    "mutex",
    "new",
    "numeric",
    "optional",
    "ostream",
    "queue",
    "random",
    "ranges",
    "ratio",
    "regex",
    "scoped_allocator",
    "set",
    "shared_mutex",
    "span",
    "sstream",
    "stack",
    "stdexcept",
    "streambuf",
    "string",
    "string_view",
    "system_error",
    "thread",
    "tuple",
    "type_traits",
    "typeindex",
    "typeinfo",
    "unordered_map",
    "unordered_set",
    "utility",
    "valarray",
    "variant",
    "vector",
}

SYSTEM_HEADERS = {
    "errno.h",
    "fcntl.h",
    "ifaddrs.h",
    "netdb.h",
    "poll.h",
    "pthread.h",
    "signal.h",
    "stdint.h",
    "stdio.h",
    "stdlib.h",
    "string.h",
    "syslog.h",
    "unistd.h",
    "time.h",
    "math.h",
    "stddef.h",
}

SYSTEM_PREFIXES = (
    "sys/",
    "net/",
    "arpa/",
    "netinet/",
    "linux/",
    "mach/",
)

THIRD_PARTY_PREFIXES = (
    "asio/",
    "gtest/",
    "gmock/",
    "openssl/",
    "rapidjson/",
    "spdlog/",
)

EXCLUDE_BASENAMES = {"log.cpp", "log.h", "reflect.h"}

INCLUDE_RE = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]')


def is_extern_syntax_line(stripped_line: str) -> bool:
    return (
        stripped_line.startswith('extern "C"')
        or stripped_line.startswith("{")
        or stripped_line.startswith("}")
    )


def repo_root() -> Path:
    here = Path(__file__).resolve()
    return here.parent.parent


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


def build_clang_args(root: Path) -> List[str]:
    return [
        "-x",
        "c++",
        "-std=c++23",
        f"-I{root}",
        f"-I{root / 'third' / 'asio' / 'include'}",
        f"-I{root / 'third' / 'spdlog' / 'include'}",
        f"-I{root / 'third' / 'rapidjson' / 'include'}",
    ]


def same_file(path_a: str, path_b: str) -> bool:
    try:
        return os.path.samefile(path_a, path_b)
    except Exception:
        return os.path.abspath(path_a) == os.path.abspath(path_b)


def fallback_extern_c_blocks(lines: List[str]) -> List[Tuple[int, int]]:
    blocks: List[Tuple[int, int]] = []
    i = 0
    n = len(lines)
    while i < n:
        if 'extern "C"' not in lines[i]:
            i += 1
            continue
        if "{" in lines[i]:
            k = i
        else:
            k = i + 1
            while k < n and lines[k].strip() == "":
                k += 1
            if k >= n or "{" not in lines[k]:
                i += 1
                continue
        brace_depth = 0
        end = None
        for m in range(k, n):
            brace_depth += lines[m].count("{")
            brace_depth -= lines[m].count("}")
            if brace_depth == 0:
                end = m + 1
                break
        if end is None:
            i += 1
            continue
        snippet = lines[i:end]
        if not any("#include" in line for line in snippet):
            i = end
            continue
        blocks.append((i + 1, end))
        i = end
    return blocks


def find_extern_c_blocks(
    path: Path, lines: List[str], clang_args: List[str], index: Optional[cindex.Index] = None
) -> List[Tuple[int, int]]:
    if index is None:
        index = cindex.Index.create()
    options = (
        cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
        | cindex.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES
    )
    try:
        tu = index.parse(str(path), args=clang_args, options=options)
    except Exception:
        return fallback_extern_c_blocks(lines)

    blocks: List[Tuple[int, int]] = []
    for cursor in tu.cursor.walk_preorder():
        if cursor.kind != cindex.CursorKind.LINKAGE_SPEC:
            continue
        loc = cursor.location
        if not loc.file or not same_file(loc.file.name, str(path)):
            continue
        start = cursor.extent.start.line
        end = cursor.extent.end.line
        if start <= 0 or end <= 0 or start > end or end > len(lines):
            continue
        snippet = lines[start - 1 : end]
        if any('extern "C"' in line for line in snippet) and any("#include" in line for line in snippet):
            blocks.append((start, end))

    if not blocks and any('extern "C"' in line for line in lines):
        return fallback_extern_c_blocks(lines)
    return blocks


def classify_include(path: str, quoted: bool) -> int:
    if quoted:
        return 3
    if path in STANDARD_HEADERS or path in SYSTEM_HEADERS:
        return 1
    if any(path.startswith(prefix) for prefix in SYSTEM_PREFIXES):
        return 1
    if any(path.startswith(prefix) for prefix in THIRD_PARTY_PREFIXES):
        return 2
    if "/" in path:
        return 2
    # Angle-bracket headers without slash are usually standard/system headers.
    return 1


def include_len(path: str, quoted: bool) -> int:
    if quoted:
        return len(f'#include "{path}"')
    return len(f"#include <{path}>")


def include_root(path: str, quoted: bool) -> Optional[str]:
    if quoted:
        return None
    if "/" not in path:
        return None
    return path.split("/", 1)[0]


class IncludeItem:
    def __init__(self, line: str, path: str, quoted: bool) -> None:
        self.line = line
        self.path = path
        self.quoted = quoted

    def sort_key(self) -> Tuple[int, str]:
        return (include_len(self.path, self.quoted), self.line)


class ExternBlockItem:
    def __init__(self, includes: List[IncludeItem]) -> None:
        self.includes = includes

    def sort_key(self) -> Tuple[int, str]:
        if not self.includes:
            return (0, "")
        smallest = min(self.includes, key=lambda i: i.sort_key())
        return (smallest.sort_key()[0], smallest.line)

    def render(self) -> List[str]:
        sorted_includes = sorted(self.includes, key=lambda i: i.sort_key())
        lines = ['extern "C"', "{"] + [inc.line for inc in sorted_includes] + ["}"]
        return lines


def parse_include_blocks(
    lines: List[str], extern_blocks: List[Tuple[int, int]]
) -> List[Tuple[int, int, List[object]]]:
    extern_start = {s: e for s, e in extern_blocks}
    extern_ranges = []
    for s, e in extern_blocks:
        extern_ranges.append((s, e))

    def in_extern_block(line_no: int) -> Optional[Tuple[int, int]]:
        for s, e in extern_ranges:
            if s <= line_no <= e:
                return (s, e)
        return None

    blocks = []
    i = 0
    n = len(lines)
    while i < n:
        line_no = i + 1
        line = lines[i]
        is_include = INCLUDE_RE.match(line) is not None
        in_extern = in_extern_block(line_no) is not None
        if not is_include and not in_extern:
            i += 1
            continue
        start = i
        i += 1
        while i < n:
            line_no = i + 1
            if lines[i].strip() == "":
                i += 1
                continue
            is_include = INCLUDE_RE.match(lines[i]) is not None
            if is_include or in_extern_block(line_no) is not None:
                i += 1
                continue
            break
        end = i

        items: List[object] = []
        j = start
        while j < end:
            line_no = j + 1
            line = lines[j]
            if line_no in extern_start:
                block_end = extern_start[line_no]
                block_lines = lines[j:block_end]
                include_items: List[IncludeItem] = []
                other_lines: List[str] = []
                for raw in block_lines:
                    m = INCLUDE_RE.match(raw)
                    if m:
                        include_items.append(IncludeItem(raw.strip(), m.group(2), m.group(1) == '"'))
                    else:
                        stripped = raw.strip()
                        if stripped and not is_extern_syntax_line(stripped):
                            other_lines.append(raw)
                if other_lines:
                    # Keep raw block untouched if it contains other tokens.
                    items.append({"raw": block_lines})
                else:
                    items.append(ExternBlockItem(include_items))
                j = block_end
                continue

            m = INCLUDE_RE.match(line)
            if m:
                items.append(IncludeItem(line.strip(), m.group(2), m.group(1) == '"'))
            j += 1

        blocks.append((start, end, items))

    return blocks


def rebuild_block(items: List[object]) -> List[str]:
    extern_root_map: Dict[str, ExternBlockItem] = {}
    for item in items:
        if isinstance(item, ExternBlockItem):
            for inc in item.includes:
                root = include_root(inc.path, inc.quoted)
                if root is None:
                    continue
                if root not in extern_root_map:
                    extern_root_map[root] = item

    groups = {1: [], 2: [], 3: [], 4: []}
    for item in items:
        if isinstance(item, IncludeItem):
            root = include_root(item.path, item.quoted)
            if root is not None and root in extern_root_map:
                extern_root_map[root].includes.append(item)
                continue
            group = classify_include(item.path, item.quoted)
            if group == 3:
                groups[4].append(item)
            else:
                groups[group].append(item)
        elif isinstance(item, ExternBlockItem):
            groups[3].append(item)
        elif isinstance(item, dict) and "raw" in item:
            groups[3].append(item)

    rendered: List[str] = []
    order = [g for g in (1, 2, 3, 4) if groups[g]]
    for idx, group in enumerate(order):
        group_items = groups[group]
        group_items_sorted = sorted(
            group_items,
            key=lambda it: it.sort_key() if hasattr(it, "sort_key") else (0, ""),
        )
        for it in group_items_sorted:
            if isinstance(it, IncludeItem):
                rendered.append(it.line)
            elif isinstance(it, ExternBlockItem):
                rendered.extend(it.render())
            elif isinstance(it, dict) and "raw" in it:
                rendered.extend([line.rstrip() for line in it["raw"]])
        if idx != len(order) - 1:
            rendered.append("")
    return rendered


def group_name(group: int) -> str:
    if group == 1:
        return "standard"
    if group == 2:
        return "third_party"
    if group == 3:
        return "extern_c"
    if group == 4:
        return "project"
    return "unknown"


def include_group(item: object) -> int:
    if isinstance(item, IncludeItem):
        group = classify_include(item.path, item.quoted)
        if group == 3:
            return 4
        return group
    if isinstance(item, ExternBlockItem):
        return 3
    if isinstance(item, dict) and "raw" in item:
        return 3
    return 0


def detect_order_issues(include_blocks: List[Tuple[int, int, List[object]]]) -> List[str]:
    issues: List[str] = []
    for block_index, (_, _, items) in enumerate(include_blocks, start=1):
        prev_group = 0
        seen_groups: Set[int] = set()
        group_items: Dict[int, List[object]] = {1: [], 2: [], 3: [], 4: []}

        for item_index, item in enumerate(items, start=1):
            group = include_group(item)
            if group == 0:
                continue
            if group < prev_group:
                issues.append(
                    f"include block {block_index}: group order broken near item {item_index}"
                )
            if group != prev_group:
                if group in seen_groups:
                    issues.append(
                        f"include block {block_index}: group {group_name(group)} is split into multiple segments"
                    )
                seen_groups.add(group)
            prev_group = group
            group_items[group].append(item)

            if isinstance(item, dict) and "raw" in item:
                issues.append(
                    f"include block {block_index}: extern-c raw block contains non-include tokens"
                )

        for group in (1, 2, 4):
            includes = [it for it in group_items[group] if isinstance(it, IncludeItem)]
            keys = [it.sort_key() for it in includes]
            if keys != sorted(keys):
                issues.append(
                    f"include block {block_index}: group {group_name(group)} is not sorted by length"
                )

        extern_blocks = [it for it in group_items[3] if isinstance(it, ExternBlockItem)]
        extern_keys = [it.sort_key() for it in extern_blocks]
        if extern_keys != sorted(extern_keys):
            issues.append(f"include block {block_index}: group extern_c blocks are not sorted")
        for extern_index, extern_block in enumerate(extern_blocks, start=1):
            include_keys = [inc.sort_key() for inc in extern_block.includes]
            if include_keys != sorted(include_keys):
                issues.append(
                    f"include block {block_index}: extern_c block {extern_index} includes are not sorted by length"
                )
    return issues


def detect_mixed_extern_roots(lines: List[str], extern_blocks: List[Tuple[int, int]]) -> List[str]:
    roots_state: Dict[str, Set[str]] = {}

    def in_extern(line_no: int) -> bool:
        for start, end in extern_blocks:
            if start <= line_no <= end:
                return True
        return False

    for idx, line in enumerate(lines, start=1):
        match = INCLUDE_RE.match(line)
        if not match:
            continue
        root = include_root(match.group(2), match.group(1) == '"')
        if root is None:
            continue
        state = "in" if in_extern(idx) else "out"
        if root not in roots_state:
            roots_state[root] = set()
        roots_state[root].add(state)

    return sorted(root for root, state in roots_state.items() if len(state) > 1)


def rewrite_includes(
    path: Path, clang_args: List[str], write: bool, index: Optional[cindex.Index] = None
) -> Tuple[bool, List[str], List[str]]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    extern_blocks = find_extern_c_blocks(path, lines, clang_args, index=index)
    include_blocks = parse_include_blocks(lines, extern_blocks)
    if not include_blocks:
        mixed = detect_mixed_extern_roots(lines, extern_blocks)
        return (False, mixed, [])

    new_lines: List[str] = []
    last_end = 0
    for start, end, items in include_blocks:
        new_lines.extend(lines[last_end:start])
        new_block = rebuild_block(items)
        new_lines.extend(new_block)
        last_end = end
        # ensure a blank line after include block if the next line is non-empty
        if last_end < len(lines) and lines[last_end].strip() != "":
            new_lines.append("")

    new_lines.extend(lines[last_end:])

    # collapse multiple blank lines
    collapsed: List[str] = []
    for line in new_lines:
        if line == "" and collapsed and collapsed[-1] == "":
            continue
        collapsed.append(line)

    new_text = "\n".join(collapsed).rstrip() + "\n"
    new_extern_blocks = fallback_extern_c_blocks(collapsed)
    new_include_blocks = parse_include_blocks(collapsed, new_extern_blocks)
    mixed = detect_mixed_extern_roots(collapsed, new_extern_blocks)
    order_issues = detect_order_issues(new_include_blocks)
    if new_text != text:
        if write:
            path.write_text(new_text, encoding="utf-8")
        return (True, mixed, order_issues)
    return (False, mixed, order_issues)


def collect_files(root: Path, paths: Optional[List[str]]) -> List[Path]:
    if paths:
        files = [root / p for p in paths]
    else:
        files = git_tracked_files(root)

    filtered = []
    for p in files:
        if p.name in EXCLUDE_BASENAMES:
            continue
        rel = p.relative_to(root)
        if str(rel).startswith("third/"):
            continue
        if not p.exists() or p.suffix not in (".h", ".cpp"):
            continue
        filtered.append(p)
    return filtered


def main() -> int:
    parser = argparse.ArgumentParser(description="Sort include order using libclang.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="only report files that would change or still violate include order rules",
    )
    parser.add_argument("files", nargs="*", help="optional file list; defaults to tracked .h/.cpp")
    args = parser.parse_args()

    root = repo_root()
    clang_args = build_clang_args(root)
    files = collect_files(root, args.files)
    index = cindex.Index.create()

    changed = []
    mixed_issues: List[str] = []
    order_issues: List[str] = []
    for path in files:
        changed_file, mixed_roots, per_file_order_issues = rewrite_includes(
            path, clang_args, write=not args.check, index=index
        )
        if changed_file:
            changed.append(str(path.relative_to(root)))
        if mixed_roots:
            mixed_issues.append(
                f"{path.relative_to(root)}: mixed extern-c include roots: {', '.join(mixed_roots)}"
            )
        for issue in per_file_order_issues:
            order_issues.append(f"{path.relative_to(root)}: {issue}")

    if changed:
        print("\n".join(changed))
    if mixed_issues:
        print("\n".join(mixed_issues), file=sys.stderr)
    if order_issues:
        print("\n".join(order_issues), file=sys.stderr)
    if args.check and (changed or mixed_issues or order_issues):
        return 2
    if mixed_issues or order_issues:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
