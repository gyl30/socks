#!/usr/bin/env python3

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def parse_input_spec(spec):
    if "=" in spec:
        label, path_text = spec.split("=", 1)
        label = label.strip()
        path = Path(path_text.strip())
    else:
        path = Path(spec.strip())
        label = path.parent.name or path.stem
    if not label:
        raise ValueError(f"invalid input label in {spec!r}")
    return label, path


def load_summary(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    processes = data.get("processes", {})
    if not processes:
        raise ValueError(f"missing processes in {path}")
    for process_name, proc in processes.items():
        if "time_series" not in proc:
            raise ValueError(
                f"{path} missing processes.{process_name}.time_series; "
                "please rerun with the updated process_resource_monitor.py"
            )
    return data


def build_cpu_curve(proc):
    series = proc.get("time_series", [])
    if len(series) < 2:
        return [0.0], [0.0]

    xs = []
    ys = []
    prev = series[0]
    for current in series[1:]:
        delta_ms = current["t_ms"] - prev["t_ms"]
        if delta_ms <= 0:
            prev = current
            continue
        delta_sec = delta_ms / 1000.0
        delta_cpu = max(0.0, float(current["cpu_seconds"]) - float(prev["cpu_seconds"]))
        xs.append(current["t_ms"] / 1000.0)
        ys.append((delta_cpu / delta_sec) * 100.0)
        prev = current

    if not xs:
        return [0.0], [0.0]
    return xs, ys


def compute_process_metrics(proc, plateau_ratio):
    series = proc.get("time_series", [])
    if not series:
        return {
            "duration_s": 0.0,
            "peak_rss_kb": int(proc.get("peak_rss_kb", 0)),
            "peak_rss_mib": float(proc.get("peak_rss_kb", 0)) / 1024.0,
            "peak_rss_t_s": 0.0,
            "plateau_ratio": plateau_ratio,
            "plateau_threshold_kb": 0,
            "plateau_start_s": 0.0,
            "plateau_end_s": 0.0,
            "plateau_duration_s": 0.0,
            "plateau_avg_rss_mib": 0.0,
            "mean_cpu_pct": 0.0,
            "peak_cpu_pct": 0.0,
        }

    peak_sample = max(series, key=lambda item: item["rss_kb"])
    peak_rss_kb = int(peak_sample["rss_kb"])
    plateau_threshold_kb = int(peak_rss_kb * plateau_ratio)
    plateau_samples = [sample for sample in series if sample["rss_kb"] >= plateau_threshold_kb]
    cpu_xs, cpu_ys = build_cpu_curve(proc)

    plateau_start_s = plateau_samples[0]["t_ms"] / 1000.0 if plateau_samples else 0.0
    plateau_end_s = plateau_samples[-1]["t_ms"] / 1000.0 if plateau_samples else 0.0
    plateau_duration_s = max(0.0, plateau_end_s - plateau_start_s)
    plateau_avg_rss_mib = (
        sum(sample["rss_kb"] for sample in plateau_samples) / len(plateau_samples) / 1024.0 if plateau_samples else 0.0
    )

    return {
        "duration_s": series[-1]["t_ms"] / 1000.0,
        "peak_rss_kb": peak_rss_kb,
        "peak_rss_mib": peak_rss_kb / 1024.0,
        "peak_rss_t_s": peak_sample["t_ms"] / 1000.0,
        "plateau_ratio": plateau_ratio,
        "plateau_threshold_kb": plateau_threshold_kb,
        "plateau_start_s": plateau_start_s,
        "plateau_end_s": plateau_end_s,
        "plateau_duration_s": plateau_duration_s,
        "plateau_avg_rss_mib": plateau_avg_rss_mib,
        "mean_cpu_pct": sum(cpu_ys) / len(cpu_ys) if cpu_ys else 0.0,
        "peak_cpu_pct": max(cpu_ys) if cpu_ys else 0.0,
    }


def build_run(label, summary_path, plateau_ratio):
    summary_path = Path(summary_path)
    data = load_summary(summary_path)
    metrics = {}
    for process_name, proc in data["processes"].items():
        metrics[process_name] = compute_process_metrics(proc, plateau_ratio)
    return {
        "label": label,
        "summary_path": str(summary_path),
        "data": data,
        "metrics": metrics,
    }


def plot_runs(runs, output_path, title, processes):
    if not runs:
        raise ValueError("no runs to plot")

    output_path = Path(output_path)
    fig, axes = plt.subplots(2, len(processes), figsize=(7.0 * len(processes), 8.0), squeeze=False, constrained_layout=True)

    for col, process_name in enumerate(processes):
        rss_ax = axes[0][col]
        cpu_ax = axes[1][col]

        for run in runs:
            proc = run["data"]["processes"].get(process_name)
            if proc is None:
                continue
            series = proc.get("time_series", [])
            if not series:
                continue

            time_s = [sample["t_ms"] / 1000.0 for sample in series]
            rss_mib = [sample["rss_kb"] / 1024.0 for sample in series]
            cpu_time_s, cpu_pct = build_cpu_curve(proc)
            rss_ax.plot(time_s, rss_mib, linewidth=1.8, label=run["label"])
            cpu_ax.plot(cpu_time_s, cpu_pct, linewidth=1.5, label=run["label"])

        rss_ax.set_title(f"{process_name} RSS")
        rss_ax.set_ylabel("RSS (MiB)")
        rss_ax.grid(True, alpha=0.3)

        cpu_ax.set_title(f"{process_name} CPU")
        cpu_ax.set_xlabel("Time (s)")
        cpu_ax.set_ylabel("CPU (%)")
        cpu_ax.grid(True, alpha=0.3)

    handles, labels = axes[0][0].get_legend_handles_labels()
    if handles:
        fig.legend(handles, labels, loc="upper center", ncol=min(len(handles), 4))

    if title:
        fig.suptitle(title)

    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def write_summary(runs, output_path):
    payload = {
        "runs": [
            {
                "label": run["label"],
                "summary_path": run["summary_path"],
                "metrics": run["metrics"],
            }
            for run in runs
        ]
    }
    Path(output_path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Plot RSS and CPU curves from resource-summary.json")
    parser.add_argument("--input", action="append", required=True, help="LABEL=resource-summary.json or resource-summary.json")
    parser.add_argument("--output", required=True, help="output image path, e.g. curves.png")
    parser.add_argument("--summary-json", default="", help="optional derived metrics json output")
    parser.add_argument("--title", default="", help="figure title")
    parser.add_argument("--processes", default="server,client", help="comma-separated process labels to plot")
    parser.add_argument("--plateau-ratio", type=float, default=0.9, help="ratio used to define the high RSS platform")
    args = parser.parse_args()

    processes = [item.strip() for item in args.processes.split(",") if item.strip()]
    runs = [build_run(label, path, args.plateau_ratio) for label, path in (parse_input_spec(spec) for spec in args.input)]
    plot_runs(runs, args.output, args.title, processes)
    if args.summary_json:
        write_summary(runs, args.summary_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
