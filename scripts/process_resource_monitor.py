#!/usr/bin/env python3

import argparse
import json
import os
import signal
import time


running = True


def handle_signal(_signum, _frame):
    global running
    running = False


def read_status(pid):
    status = {}
    with open(f"/proc/{pid}/status", "r", encoding="utf-8") as handle:
        for line in handle:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            status[key] = value.strip()
    return status


def read_cpu_seconds(pid):
    with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as handle:
        fields = handle.read().split()
    ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    user_ticks = int(fields[13])
    system_ticks = int(fields[14])
    return (user_ticks + system_ticks) / ticks


def parse_kb(status, field):
    value = status.get(field, "0 kB").split()[0]
    return int(value)


def parse_int(status, field):
    return int(status.get(field, "0"))


def sample_process(pid):
    status = read_status(pid)
    fd_count = len(os.listdir(f"/proc/{pid}/fd"))
    return {
        "rss_kb": parse_kb(status, "VmRSS"),
        "hwm_kb": parse_kb(status, "VmHWM"),
        "vm_size_kb": parse_kb(status, "VmSize"),
        "threads": parse_int(status, "Threads"),
        "fd_count": fd_count,
        "cpu_seconds": read_cpu_seconds(pid),
    }


def main():
    parser = argparse.ArgumentParser(description="Sample process resource usage from /proc")
    parser.add_argument("--pid", action="append", required=True, help="label:pid")
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    targets = {}
    for entry in args.pid:
        label, pid_text = entry.split(":", 1)
        targets[label] = int(pid_text)

    summary = {
        "interval_ms": args.interval_ms,
        "started_at": time.time(),
        "processes": {},
    }

    for label, pid in targets.items():
        initial_sample = sample_process(pid)
        summary["processes"][label] = {
            "pid": pid,
            "initial": initial_sample,
            "final": initial_sample,
            "peak_rss_kb": initial_sample["rss_kb"],
            "peak_hwm_kb": initial_sample["hwm_kb"],
            "peak_vm_size_kb": initial_sample["vm_size_kb"],
            "peak_threads": initial_sample["threads"],
            "peak_fd_count": initial_sample["fd_count"],
            "cpu_seconds_start": initial_sample["cpu_seconds"],
            "cpu_seconds_end": initial_sample["cpu_seconds"],
            "samples": 1,
        }

    sleep_interval = args.interval_ms / 1000.0
    while running:
        time.sleep(sleep_interval)
        for label, pid in targets.items():
            if not os.path.exists(f"/proc/{pid}"):
                continue
            sample = sample_process(pid)
            proc_summary = summary["processes"][label]
            proc_summary["final"] = sample
            proc_summary["peak_rss_kb"] = max(proc_summary["peak_rss_kb"], sample["rss_kb"])
            proc_summary["peak_hwm_kb"] = max(proc_summary["peak_hwm_kb"], sample["hwm_kb"])
            proc_summary["peak_vm_size_kb"] = max(proc_summary["peak_vm_size_kb"], sample["vm_size_kb"])
            proc_summary["peak_threads"] = max(proc_summary["peak_threads"], sample["threads"])
            proc_summary["peak_fd_count"] = max(proc_summary["peak_fd_count"], sample["fd_count"])
            proc_summary["cpu_seconds_end"] = sample["cpu_seconds"]
            proc_summary["samples"] += 1

    summary["finished_at"] = time.time()
    summary["duration_seconds"] = summary["finished_at"] - summary["started_at"]
    for proc_summary in summary["processes"].values():
        proc_summary["cpu_seconds_total"] = proc_summary["cpu_seconds_end"] - proc_summary["cpu_seconds_start"]

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
