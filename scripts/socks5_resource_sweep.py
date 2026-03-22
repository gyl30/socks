#!/usr/bin/env python3

import argparse
import csv
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from plot_resource_curves import build_run, plot_runs, write_summary


def parse_assignment(text):
    if "=" not in text:
        raise ValueError(f"invalid assignment {text!r}, expected NAME=VALUE")
    name, value = text.split("=", 1)
    name = name.strip()
    value = value.strip()
    if not name or not value:
        raise ValueError(f"invalid assignment {text!r}, expected NAME=VALUE")
    return name, value


def parse_axis(text):
    name, values_text = parse_assignment(text)
    values = [item.strip() for item in values_text.split(",") if item.strip()]
    if not values:
        raise ValueError(f"invalid axis {text!r}, expected NAME=v1,v2,...")
    return name, values


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


def parse_artifact_dir(text):
    match = re.search(r"kept at (\S+)", text)
    if match is None:
        return None
    return Path(match.group(1))


def to_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def format_env_overrides(env_overrides):
    return ", ".join(f"{name}={value}" for name, value in env_overrides.items())


def extract_metrics(resource_summary, load_metrics, run_plot):
    server = resource_summary["processes"]["server"]
    client = resource_summary["processes"]["client"]
    server_metrics = run_plot["metrics"].get("server", {})
    client_metrics = run_plot["metrics"].get("client", {})

    throughput = to_float(load_metrics.get("throughput_mib_per_s"))
    total_cpu_seconds = to_float(server.get("cpu_seconds_total")) + to_float(client.get("cpu_seconds_total"))
    server_peak_rss_mib = to_float(server.get("peak_rss_kb")) / 1024.0

    return {
        "connections": to_int(load_metrics.get("connections")),
        "bytes": to_int(load_metrics.get("bytes")),
        "duration_seconds": to_float(load_metrics.get("duration_seconds"), to_float(resource_summary.get("duration_seconds"))),
        "throughput_mib_per_s": throughput,
        "server_peak_rss_kb": to_int(server.get("peak_rss_kb")),
        "server_peak_rss_mib": server_peak_rss_mib,
        "client_peak_rss_kb": to_int(client.get("peak_rss_kb")),
        "client_peak_rss_mib": to_float(client.get("peak_rss_kb")) / 1024.0,
        "server_cpu_seconds_total": to_float(server.get("cpu_seconds_total")),
        "client_cpu_seconds_total": to_float(client.get("cpu_seconds_total")),
        "server_peak_cpu_pct": to_float(server_metrics.get("peak_cpu_pct")),
        "server_mean_cpu_pct": to_float(server_metrics.get("mean_cpu_pct")),
        "client_peak_cpu_pct": to_float(client_metrics.get("peak_cpu_pct")),
        "client_mean_cpu_pct": to_float(client_metrics.get("mean_cpu_pct")),
        "server_plateau_duration_s": to_float(server_metrics.get("plateau_duration_s")),
        "server_plateau_avg_rss_mib": to_float(server_metrics.get("plateau_avg_rss_mib")),
        "client_plateau_duration_s": to_float(client_metrics.get("plateau_duration_s")),
        "client_plateau_avg_rss_mib": to_float(client_metrics.get("plateau_avg_rss_mib")),
        "throughput_per_server_peak_rss": throughput / server_peak_rss_mib if server_peak_rss_mib > 0 else 0.0,
        "throughput_per_total_cpu_second": throughput / total_cpu_seconds if total_cpu_seconds > 0 else 0.0,
    }


def write_csv(records, csv_path):
    env_keys = sorted({key for record in records for key in record["env"].keys()})
    metric_keys = sorted({key for record in records for key in record.get("metrics", {}).keys()})
    fieldnames = ["run", "status", "artifact_dir"] + env_keys + metric_keys

    with open(csv_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            row = {
                "run": record["run"],
                "status": record["status"],
                "artifact_dir": record.get("artifact_dir", ""),
            }
            row.update(record["env"])
            row.update(record.get("metrics", {}))
            writer.writerow(row)


def write_markdown(records, output_path):
    success_records = [record for record in records if record["status"] == "ok"]
    success_records.sort(key=lambda item: item.get("metrics", {}).get("throughput_per_server_peak_rss", 0.0), reverse=True)

    lines = [
        "# SOCKS5 Resource Sweep",
        "",
        f"- total_runs: {len(records)}",
        f"- successful_runs: {len(success_records)}",
        "",
        "| run | status | throughput MiB/s | server peak RSS MiB | server peak CPU % | server plateau s | score throughput/rss | env |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for record in success_records:
        metrics = record["metrics"]
        lines.append(
            "| "
            + " | ".join(
                [
                    record["run"],
                    record["status"],
                    f"{metrics.get('throughput_mib_per_s', 0.0):.2f}",
                    f"{metrics.get('server_peak_rss_mib', 0.0):.2f}",
                    f"{metrics.get('server_peak_cpu_pct', 0.0):.2f}",
                    f"{metrics.get('server_plateau_duration_s', 0.0):.2f}",
                    f"{metrics.get('throughput_per_server_peak_rss', 0.0):.2f}",
                    format_env_overrides(record['env']),
                ]
            )
            + " |"
        )
    failed_records = [record for record in records if record["status"] != "ok"]
    if failed_records:
        lines.extend(["", "## Failed Runs", ""])
        for record in failed_records:
            lines.append(f"- {record['run']}: {format_env_overrides(record['env'])}")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_case(repo_root, binary, env_overrides, run_dir, plateau_ratio, processes):
    run_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = run_dir / "command.stdout.log"
    stderr_path = run_dir / "command.stderr.log"

    env = os.environ.copy()
    env.update(env_overrides)
    env["KEEP_TEST_ARTIFACTS"] = "1"

    command = ["bash", str(repo_root / "scripts/test_socks5_resource.sh"), str(binary)]
    result = subprocess.run(command, cwd=repo_root, env=env, text=True, capture_output=True)
    stdout_path.write_text(result.stdout, encoding="utf-8")
    stderr_path.write_text(result.stderr, encoding="utf-8")

    combined_output = result.stdout + "\n" + result.stderr
    artifact_dir = parse_artifact_dir(combined_output)
    moved_artifact_dir = None
    if artifact_dir is not None and artifact_dir.exists():
        moved_artifact_dir = run_dir / "artifacts"
        if moved_artifact_dir.exists():
            shutil.rmtree(moved_artifact_dir)
        shutil.move(str(artifact_dir), str(moved_artifact_dir))

    record = {
        "run": run_dir.name,
        "status": "ok" if result.returncode == 0 else "failed",
        "env": dict(env_overrides),
        "artifact_dir": str(moved_artifact_dir) if moved_artifact_dir is not None else "",
    }

    if moved_artifact_dir is None:
        record["error"] = "artifact directory not found"
        return record

    resource_json = moved_artifact_dir / "resource-summary.json"
    load_summary_log = moved_artifact_dir / "load-summary.log"
    if not resource_json.exists():
        record["error"] = "resource-summary.json not found"
        return record

    resource_summary = json.loads(resource_json.read_text(encoding="utf-8"))
    load_metrics = parse_key_value_file(load_summary_log)
    run_plot = build_run(run_dir.name, resource_json, plateau_ratio)
    plot_runs(
        [run_plot],
        run_dir / "curves.png",
        f"{run_dir.name}  {format_env_overrides(env_overrides)}",
        processes,
    )
    write_summary([run_plot], run_dir / "derived-metrics.json")
    record["metrics"] = extract_metrics(resource_summary, load_metrics, run_plot)
    return record


def main():
    parser = argparse.ArgumentParser(description="Sweep SOCKS5 resource test parameters and render RSS/CPU curves")
    parser.add_argument("--binary", default=str(Path("build") / "socks"), help="path to socks binary")
    parser.add_argument("--axis", action="append", default=[], help="NAME=v1,v2,... environment-variable sweep axis")
    parser.add_argument("--fixed", action="append", default=[], help="NAME=VALUE fixed environment-variable override")
    parser.add_argument("--output-root", default="", help="directory for sweep results")
    parser.add_argument("--plateau-ratio", type=float, default=0.9)
    parser.add_argument("--processes", default="server,client", help="comma-separated processes for curve plots")
    parser.add_argument("--stop-on-error", action="store_true", help="stop immediately if one sweep run fails")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    binary = Path(args.binary)
    if not binary.is_absolute():
        binary = (repo_root / binary).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"binary not found: {binary}")

    fixed_env = dict(parse_assignment(item) for item in args.fixed)
    axes = [parse_axis(item) for item in args.axis]
    axis_names = [name for name, _values in axes]
    axis_values = [values for _name, values in axes]
    combinations = list(itertools.product(*axis_values)) if axis_values else [()]

    if args.output_root:
        output_root = Path(args.output_root)
        if not output_root.is_absolute():
            output_root = (repo_root / output_root).resolve()
    else:
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        output_root = repo_root / "reports" / "resource-review" / timestamp / "sweep"
    output_root.mkdir(parents=True, exist_ok=True)
    processes = [item.strip() for item in args.processes.split(",") if item.strip()]

    records = []
    successful_plot_runs = []

    for index, combination in enumerate(combinations, start=1):
        run_env = dict(fixed_env)
        run_env.update({name: value for name, value in zip(axis_names, combination)})
        run_dir = output_root / f"run-{index:03d}"
        print(f"[{index}/{len(combinations)}] {format_env_overrides(run_env)}", file=sys.stderr)
        record = run_case(repo_root, binary, run_env, run_dir, args.plateau_ratio, processes)
        records.append(record)

        if record["status"] == "ok":
            resource_json = Path(record["artifact_dir"]) / "resource-summary.json"
            successful_plot_runs.append(build_run(record["run"], resource_json, args.plateau_ratio))
        elif args.stop_on_error:
            break

    summary_json_path = output_root / "summary.json"
    summary_csv_path = output_root / "summary.csv"
    summary_md_path = output_root / "summary.md"
    summary_json_path.write_text(json.dumps({"runs": records}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_csv(records, summary_csv_path)
    write_markdown(records, summary_md_path)

    if successful_plot_runs:
        plot_runs(
            successful_plot_runs,
            output_root / "all-runs-curves.png",
            "SOCKS5 resource sweep",
            processes,
        )
        write_summary(successful_plot_runs, output_root / "all-runs-derived-metrics.json")

    print(f"results kept at {output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
