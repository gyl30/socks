#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List


def parse_capacities(text: str) -> List[int]:
    values: List[int] = []
    for part in text.split(","):
        token = part.strip()
        if not token:
            continue
        capacity = int(token)
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        if capacity not in values:
            values.append(capacity)
    if not values:
        raise ValueError("no capacities provided")
    return values


def average(values: List[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / float(len(values))


def average_optional(values: List[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / float(len(values))


def parse_prefixed_json_line(output: str, prefix: str) -> Dict[str, object]:
    for line in output.splitlines():
        if line.startswith(prefix):
            payload = line[len(prefix) :].strip()
            return json.loads(payload)
    raise RuntimeError(f"missing output line: {prefix}")


def run_once(
    test_script: str,
    socks_bin: str,
    capacity: int,
    run_index: int,
    burst_count: int,
    payload_bytes: int,
    timeout_ms: int,
) -> Dict[str, object]:
    env = os.environ.copy()
    env.update(
        {
            "BIN": socks_bin,
            "TPROXY_QUEUE_CAPACITY": str(capacity),
            "UDP_BURST_COUNT": str(burst_count),
            "UDP_BURST_PAYLOAD_BYTES": str(payload_bytes),
            "UDP_BURST_TIMEOUT_MS": str(timeout_ms),
        }
    )

    started = time.perf_counter()
    proc = subprocess.run(
        ["bash", test_script],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    elapsed = time.perf_counter() - started

    if proc.returncode == 77:
        raise RuntimeError("tproxy integration test skipped (need root privilege or required commands)")
    if proc.returncode != 0:
        raise RuntimeError(
            f"tproxy integration test failed for capacity={capacity} run={run_index} rc={proc.returncode}\n{proc.stdout}"
        )

    burst = parse_prefixed_json_line(proc.stdout, "TPROXY_PERF_BURST ")
    dispatch = parse_prefixed_json_line(proc.stdout, "TPROXY_PERF_DISPATCH ")
    return {
        "queue_capacity": capacity,
        "run_index": run_index,
        "suite_wall_time_sec": round(elapsed, 3),
        "udp_burst": burst,
        "dispatch": dispatch,
    }


def aggregate(results: List[Dict[str, object]]) -> List[Dict[str, object]]:
    grouped: Dict[int, List[Dict[str, object]]] = {}
    for item in results:
        cap = int(item["queue_capacity"])
        grouped.setdefault(cap, []).append(item)

    summary: List[Dict[str, object]] = []
    for capacity in sorted(grouped):
        runs = grouped[capacity]
        throughput = [float(run["udp_burst"]["throughput_mbps"]) for run in runs]
        loss = [float(run["udp_burst"]["packet_loss_rate"]) for run in runs]
        p95 = [float(run["udp_burst"]["rtt_p95_ms"]) for run in runs if run["udp_burst"]["rtt_p95_ms"] is not None]
        p99 = [float(run["udp_burst"]["rtt_p99_ms"]) for run in runs if run["udp_burst"]["rtt_p99_ms"] is not None]
        dispatch_drop = [float(run["dispatch"]["drop_ratio"]) for run in runs]
        suite_wall = [float(run["suite_wall_time_sec"]) for run in runs]
        summary.append(
            {
                "queue_capacity": capacity,
                "runs": len(runs),
                "throughput_mbps_avg": round(average(throughput), 3),
                "packet_loss_rate_avg": round(average(loss), 5),
                "rtt_p95_ms_avg": round(average_optional(p95), 3) if p95 else None,
                "rtt_p99_ms_avg": round(average_optional(p99), 3) if p99 else None,
                "dispatch_drop_ratio_avg": round(average(dispatch_drop), 6),
                "suite_wall_time_sec_avg": round(average(suite_wall), 3),
            }
        )
    return summary


def pick_recommended(summary: List[Dict[str, object]]) -> Dict[str, object]:
    def rank_key(item: Dict[str, object]) -> tuple:
        dispatch_drop = float(item["dispatch_drop_ratio_avg"])
        packet_loss = float(item["packet_loss_rate_avg"])
        throughput = float(item["throughput_mbps_avg"])
        p95 = item["rtt_p95_ms_avg"]
        p95_value = float(p95) if p95 is not None else float("inf")
        capacity = int(item["queue_capacity"])
        return (dispatch_drop, packet_loss, -throughput, p95_value, capacity)

    return min(summary, key=rank_key)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sweep tproxy udp dispatch queue capacity")
    parser.add_argument("--test-script", default="tests/tproxy_integration_test.sh")
    parser.add_argument("--socks-bin", default="build/socks")
    parser.add_argument("--capacities", default="256,512,1024,2048")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--burst-count", type=int, default=4000)
    parser.add_argument("--payload-bytes", type=int, default=512)
    parser.add_argument("--udp-timeout-ms", type=int, default=1000)
    parser.add_argument("--out-json", default="build_release_perf/perf_tproxy_queue_sweep_latest.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    capacities = parse_capacities(args.capacities)
    if args.runs <= 0:
        raise RuntimeError("runs must be > 0")

    test_script = str(Path(args.test_script))
    socks_bin = str(Path(args.socks_bin).resolve())

    all_runs: List[Dict[str, object]] = []
    for capacity in capacities:
        for run_index in range(args.runs):
            print(f"[tproxy-queue-sweep] capacity={capacity} run={run_index + 1}/{args.runs}", flush=True)
            result = run_once(
                test_script=test_script,
                socks_bin=socks_bin,
                capacity=capacity,
                run_index=run_index,
                burst_count=args.burst_count,
                payload_bytes=args.payload_bytes,
                timeout_ms=args.udp_timeout_ms,
            )
            all_runs.append(result)

    summary = aggregate(all_runs)
    recommended = pick_recommended(summary)
    output = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "config": {
            "test_script": test_script,
            "socks_bin": socks_bin,
            "capacities": capacities,
            "runs_per_capacity": args.runs,
            "burst_count": args.burst_count,
            "payload_bytes": args.payload_bytes,
            "udp_timeout_ms": args.udp_timeout_ms,
        },
        "runs": all_runs,
        "summary": summary,
        "recommended": recommended,
    }

    out_path = Path(args.out_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(output, indent=2, ensure_ascii=False))
    print(f"[tproxy-queue-sweep] wrote result to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
