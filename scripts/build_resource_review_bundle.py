#!/usr/bin/env python3

import argparse
import json
import os
import re
import shutil
import time
from pathlib import Path

from plot_resource_curves import build_run, plot_runs, write_summary


def parse_run_spec(spec):
    if "=" in spec:
        label, path_text = spec.split("=", 1)
        label = label.strip()
        path = Path(path_text.strip())
    else:
        path = Path(spec.strip())
        label = path.stem if path.is_file() else path.name
    if not label:
        raise ValueError(f"invalid run spec {spec!r}")
    return label, path


def slugify(text):
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", text.strip()).strip("-")
    return slug or "run"


def resolve_artifact_dir(path):
    path = Path(path)
    if path.is_dir():
        artifact_dir = path
    else:
        artifact_dir = path.parent
    resource_json = artifact_dir / "resource-summary.json"
    if not resource_json.exists():
        raise FileNotFoundError(f"{artifact_dir} missing resource-summary.json")
    return artifact_dir


def parse_key_value_file(path):
    metrics = {}
    if not path.exists():
        return metrics
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        metrics[key.strip()] = value.strip()
    return metrics


def to_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def copy_artifact_tree(source_dir, target_dir):
    if target_dir.exists():
        shutil.rmtree(target_dir)
    shutil.copytree(source_dir, target_dir)


def build_run_record(label, copied_artifact_dir, plateau_ratio):
    resource_json = copied_artifact_dir / "resource-summary.json"
    load_metrics = parse_key_value_file(copied_artifact_dir / "load-summary.log")
    run_plot = build_run(label, resource_json, plateau_ratio)
    server_metrics = run_plot["metrics"].get("server", {})
    client_metrics = run_plot["metrics"].get("client", {})
    resource_summary = json.loads(resource_json.read_text(encoding="utf-8"))
    server_proc = resource_summary["processes"]["server"]
    client_proc = resource_summary["processes"]["client"]

    return {
        "label": label,
        "artifact_dir": str(copied_artifact_dir),
        "run_plot": run_plot,
        "load_metrics": load_metrics,
        "summary": {
            "throughput_mib_per_s": to_float(load_metrics.get("throughput_mib_per_s")),
            "duration_seconds": to_float(load_metrics.get("duration_seconds"), to_float(resource_summary.get("duration_seconds"))),
            "connections": int(load_metrics.get("connections", "0") or 0),
            "server_peak_rss_mib": to_float(server_proc.get("peak_rss_kb")) / 1024.0,
            "server_peak_cpu_pct": to_float(server_metrics.get("peak_cpu_pct")),
            "server_plateau_duration_s": to_float(server_metrics.get("plateau_duration_s")),
            "client_peak_rss_mib": to_float(client_proc.get("peak_rss_kb")) / 1024.0,
            "client_peak_cpu_pct": to_float(client_metrics.get("peak_cpu_pct")),
            "client_plateau_duration_s": to_float(client_metrics.get("plateau_duration_s")),
        },
    }


def write_index(bundle_root, compare_plot_path, records, sweep_dir):
    lines = [
        "# Resource Review Bundle",
        "",
        "## Contents",
        "",
        f"- compare plot: `{compare_plot_path.relative_to(bundle_root)}`",
    ]
    if sweep_dir is not None:
        lines.append(f"- sweep report: `{sweep_dir.relative_to(bundle_root) / 'summary.md'}`")
        lines.append(f"- sweep overlay: `{sweep_dir.relative_to(bundle_root) / 'all-runs-curves.png'}`")

    lines.extend(
        [
            "",
            "## Key Runs",
            "",
            "| label | throughput MiB/s | server peak RSS MiB | server peak CPU % | server plateau s | artifact |",
            "| --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for record in records:
        summary = record["summary"]
        artifact_rel = Path(record["artifact_dir"]).relative_to(bundle_root)
        lines.append(
            "| "
            + " | ".join(
                [
                    record["label"],
                    f"{summary['throughput_mib_per_s']:.2f}",
                    f"{summary['server_peak_rss_mib']:.2f}",
                    f"{summary['server_peak_cpu_pct']:.2f}",
                    f"{summary['server_plateau_duration_s']:.2f}",
                    f"`{artifact_rel}`",
                ]
            )
            + " |"
        )

    (bundle_root / "INDEX.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def update_latest_symlink(bundle_root):
    latest_link = bundle_root.parent / "latest"
    if latest_link.is_symlink() or latest_link.is_file():
        latest_link.unlink()
    elif latest_link.is_dir():
        shutil.rmtree(latest_link)
    latest_link.symlink_to(bundle_root.name, target_is_directory=True)


def main():
    parser = argparse.ArgumentParser(description="Collect resource plots and reports into a single review bundle")
    parser.add_argument("--run", action="append", required=True, help="LABEL=artifact_dir or LABEL=resource-summary.json")
    parser.add_argument("--sweep-dir", default="", help="optional sweep output directory to copy into the bundle")
    parser.add_argument("--output-root", default="", help="bundle output directory")
    parser.add_argument("--title", default="SOCKS5 Resource Review", help="comparison figure title")
    parser.add_argument("--plateau-ratio", type=float, default=0.9)
    parser.add_argument("--no-latest-link", action="store_true", help="do not update reports/resource-review/latest")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    if args.output_root:
        bundle_root = Path(args.output_root)
        if not bundle_root.is_absolute():
            bundle_root = (repo_root / bundle_root).resolve()
    else:
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        bundle_root = repo_root / "reports" / "resource-review" / timestamp
    bundle_root.mkdir(parents=True, exist_ok=True)

    runs_root = bundle_root / "runs"
    compare_root = bundle_root / "compare"
    runs_root.mkdir(parents=True, exist_ok=True)
    compare_root.mkdir(parents=True, exist_ok=True)

    records = []
    plot_runs_input = []
    for label, source_path in (parse_run_spec(spec) for spec in args.run):
        if not source_path.is_absolute():
            source_path = (repo_root / source_path).resolve()
        artifact_dir = resolve_artifact_dir(source_path)
        target_dir = runs_root / slugify(label) / "artifacts"
        target_dir.parent.mkdir(parents=True, exist_ok=True)
        copy_artifact_tree(artifact_dir, target_dir)
        record = build_run_record(label, target_dir, args.plateau_ratio)
        plot_runs(
            [record["run_plot"]],
            target_dir.parent / "curves.png",
            f"{label} resource curves",
            ["server", "client"],
        )
        write_summary([record["run_plot"]], target_dir.parent / "derived-metrics.json")
        records.append(record)
        plot_runs_input.append(record["run_plot"])

    compare_plot = compare_root / "resource-curves.png"
    plot_runs(plot_runs_input, compare_plot, args.title, ["server", "client"])
    write_summary(plot_runs_input, compare_root / "resource-curves.json")

    copied_sweep_dir = None
    if args.sweep_dir:
        source_sweep_dir = Path(args.sweep_dir)
        if not source_sweep_dir.is_absolute():
            source_sweep_dir = (repo_root / source_sweep_dir).resolve()
        copied_sweep_dir = bundle_root / "sweep"
        if copied_sweep_dir.exists():
            shutil.rmtree(copied_sweep_dir)
        shutil.copytree(source_sweep_dir, copied_sweep_dir)

    write_index(bundle_root, compare_plot, records, copied_sweep_dir)
    if not args.no_latest_link:
        update_latest_symlink(bundle_root)

    print(f"bundle kept at {bundle_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
