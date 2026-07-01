#!/usr/bin/env python3
"""Run repeatable PSI performance sweeps and export CSV/JSONL results."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List


KV_RE = re.compile(r"([^=,\s]+)=([^,]+)")


def parse_list(value: str, cast=str) -> List:
    out = []
    for part in value.split(","):
        part = part.strip()
        if part:
            out.append(cast(part))
    return out


def parse_exps(value: str) -> List[int]:
    out: List[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            out.extend(range(int(start), int(end) + 1))
        else:
            out.append(int(part))
    return out


def parse_kv_payload(payload: str) -> Dict[str, str]:
    return {match.group(1): match.group(2).strip() for match in KV_RE.finditer(payload)}


def merge_prefixed(row: Dict[str, object], prefix: str, values: Dict[str, str]) -> None:
    for key, value in values.items():
        row[f"{prefix}_{key}"] = coerce_value(value)


def coerce_value(value: str):
    if value in {"yes", "no", "n/a"}:
        return value
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def parse_output(stdout: str) -> Dict[str, object]:
    row: Dict[str, object] = {}
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("RIE_RESULT "):
            merge_prefixed(row, "result", parse_kv_payload(line[len("RIE_RESULT ") :]))
        elif line.startswith("RIE_MEMORY "):
            merge_prefixed(row, "memory", parse_kv_payload(line[len("RIE_MEMORY ") :]))
        elif line.startswith("RIE_OFFLINE "):
            parts = line.split(" ", 2)
            if len(parts) == 3:
                merge_prefixed(row, f"offline_{parts[1]}", parse_kv_payload(parts[2]))
        elif line.startswith("RIE_METRICS "):
            parts = line.split(" ", 2)
            if len(parts) == 3:
                merge_prefixed(row, f"metrics_{parts[1]}", parse_kv_payload(parts[2]))
        elif line.startswith("RIE_NETWORK "):
            parts = line.split(" ", 2)
            if len(parts) == 3:
                merge_prefixed(row, f"network_{parts[1]}", parse_kv_payload(parts[2]))
        elif line.startswith("RIE_PROFILE "):
            parts = line.split(" ", 2)
            if len(parts) == 3:
                merge_prefixed(row, f"profile_{parts[1]}", parse_kv_payload(parts[2]))
        elif line.startswith("RIE_FRAMEWORK "):
            parts = line.split(" ", 2)
            if len(parts) == 3:
                merge_prefixed(row, f"framework_{parts[1]}", parse_kv_payload(parts[2]))
        elif line.startswith("RIE_TRANSPORT "):
            parts = line.split(" ", 2)
            if len(parts) == 3:
                merge_prefixed(row, f"transport_{parts[1]}", parse_kv_payload(parts[2]))
    return row


def run_command(
    cmd: List[str],
    cwd: Path,
    env: Dict[str, str],
    timeout: int,
) -> Dict[str, object]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        elapsed = time.perf_counter() - start
        row = parse_output(proc.stdout)
        row.update(
            {
                "runner_status": "ok" if proc.returncode == 0 else "failed",
                "runner_returncode": proc.returncode,
                "runner_wall_time": elapsed,
            }
        )
        if proc.returncode != 0:
            row["runner_stdout_tail"] = proc.stdout[-2000:]
            row["runner_stderr_tail"] = proc.stderr[-2000:]
        return row
    except subprocess.TimeoutExpired as exc:
        elapsed = time.perf_counter() - start
        return {
            "runner_status": "timeout",
            "runner_returncode": None,
            "runner_wall_time": elapsed,
            "runner_timeout": timeout,
            "runner_stdout_tail": (exc.stdout or "")[-2000:],
            "runner_stderr_tail": (exc.stderr or "")[-2000:],
        }


def write_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    keys = []
    seen = set()
    preferred = [
        "bench_id",
        "trial",
        "cmd_mode",
        "cmd_clients",
        "cmd_exp",
        "cmd_scenario",
        "runner_status",
        "runner_wall_time",
    ]
    for key in preferred:
        if any(key in row for row in rows):
            keys.append(key)
            seen.add(key)
    for row in rows:
        for key in row:
            if key not in seen:
                keys.append(key)
                seen.add(key)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)


def append_jsonl(path: Path, row: Dict[str, object]) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build-rie/psi_direct_fft_no_bucket")
    parser.add_argument(
        "--mode",
        default="protocol3-method2",
        choices=["protocol3", "protocol3-method2", "third-party-method2"],
    )
    parser.add_argument("--clients", default="2")
    parser.add_argument("--exps", required=True, help="Examples: 10,15 or 10-15")
    parser.add_argument("--scenarios", default="half")
    parser.add_argument("--intersection-rates", default="")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--gcd", default="ntl", choices=["flint", "ntl"])
    parser.add_argument("--root", default="tg", choices=["tg", "flint", "distinct"])
    parser.add_argument("--transport", default="simulated", choices=["simulated", "tcp-tls"])
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--trace", action="store_true")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--jobs", default="")
    parser.add_argument("--omp-threads", default="")
    parser.add_argument("--proc-bind", default="")
    parser.add_argument("--places", default="")
    parser.add_argument(
        "--transport-model",
        default="zhihu-linear",
        choices=["latency-bandwidth", "zhihu-linear"],
    )
    parser.add_argument(
        "--transport-profile",
        default="wan",
        choices=["lan", "wan", "custom"],
    )
    parser.add_argument("--transport-bandwidth-mbps", default="")
    parser.add_argument("--transport-latency-ms", default="")
    parser.add_argument("--transport-message-overhead-bytes", default="")
    parser.add_argument("--transport-linear-intercept", default="")
    parser.add_argument("--transport-linear-slope-per-mb", default="")
    parser.add_argument("--transport-linear-valid-min-mb", default="")
    parser.add_argument("--csv", default="bench_results.csv")
    parser.add_argument("--jsonl", default="bench_results.jsonl")
    args = parser.parse_args(list(argv))

    cwd = Path.cwd()
    binary = Path(args.binary)
    if args.build:
        build_cmd = ["cmake", "--build", "build-rie"]
        if args.jobs:
            build_cmd.extend(["--parallel", args.jobs])
        else:
            build_cmd.append("--parallel")
        subprocess.run(build_cmd, cwd=str(cwd), check=True)

    clients = parse_exps(args.clients)
    exps = parse_exps(args.exps)
    scenarios = parse_list(args.scenarios, str)
    intersection_rates = (
        parse_list(args.intersection_rates, float)
        if args.intersection_rates
        else [None]
    )

    env = os.environ.copy()
    if args.omp_threads:
        env["OMP_NUM_THREADS"] = args.omp_threads
    if args.proc_bind:
        env["OMP_PROC_BIND"] = args.proc_bind
    if args.places:
        env["OMP_PLACES"] = args.places

    csv_path = Path(args.csv)
    jsonl_path = Path(args.jsonl)
    if jsonl_path.exists():
        jsonl_path.unlink()

    rows: List[Dict[str, object]] = []
    bench_id = 0
    for exp in exps:
        for client_count in clients:
            for scenario in scenarios:
                for intersection_rate in intersection_rates:
                    for trial in range(1, args.repeats + 1):
                        bench_id += 1
                        cmd = [
                            str(binary),
                            "--mode",
                            args.mode,
                            "--clients",
                            str(client_count),
                            "--exp",
                            str(exp),
                            "--scenario",
                            scenario,
                            "--gcd",
                            args.gcd,
                            "--root",
                            args.root,
                            "--transport",
                            args.transport,
                            "--transport-model",
                            args.transport_model,
                            "--transport-profile",
                            args.transport_profile,
                        ]
                        optional_transport_args = [
                            ("--transport-bandwidth-mbps", args.transport_bandwidth_mbps),
                            ("--transport-latency-ms", args.transport_latency_ms),
                            ("--transport-message-overhead-bytes", args.transport_message_overhead_bytes),
                            ("--transport-linear-intercept", args.transport_linear_intercept),
                            ("--transport-linear-slope-per-mb", args.transport_linear_slope_per_mb),
                            ("--transport-linear-valid-min-mb", args.transport_linear_valid_min_mb),
                        ]
                        for flag, value in optional_transport_args:
                            if value:
                                cmd.extend([flag, value])
                        if intersection_rate is not None:
                            cmd.extend([
                                "--intersection-rate",
                                f"{intersection_rate:.12g}",
                            ])
                        if args.validate:
                            cmd.append("--validate")
                        if args.trace:
                            cmd.append("--trace")
                        rate_label = (
                            "default"
                            if intersection_rate is None
                            else f"{intersection_rate:.6g}"
                        )
                        print(
                            f"[{bench_id}] mode={args.mode} clients={client_count} "
                            f"exp={exp} scenario={scenario} "
                            f"intersection_rate={rate_label} trial={trial}",
                            flush=True,
                        )
                        row = run_command(cmd, cwd, env, args.timeout)
                        row.update(
                            {
                                "bench_id": bench_id,
                                "trial": trial,
                                "cmd_mode": args.mode,
                                "cmd_clients": client_count,
                                "cmd_exp": exp,
                                "cmd_scenario": scenario,
                                "cmd_intersection_rate": rate_label,
                                "cmd_root": args.root,
                                "cmd_gcd": args.gcd,
                                "cmd_transport": args.transport,
                                "cmd_validate": "yes" if args.validate else "no",
                                "cmd_transport_model": args.transport_model,
                                "cmd_transport_profile": args.transport_profile,
                                "cmd_transport_bandwidth_mbps": args.transport_bandwidth_mbps,
                                "cmd_transport_latency_ms": args.transport_latency_ms,
                                "cmd_transport_message_overhead_bytes": args.transport_message_overhead_bytes,
                                "cmd_transport_linear_intercept": args.transport_linear_intercept,
                                "cmd_transport_linear_slope_per_mb": args.transport_linear_slope_per_mb,
                                "cmd_transport_linear_valid_min_mb": args.transport_linear_valid_min_mb,
                            }
                        )
                        rows.append(row)
                        append_jsonl(jsonl_path, row)
                        print(
                            f"    status={row.get('runner_status')} "
                            f"wall={row.get('runner_wall_time'):.3f}s "
                            f"end_to_end={row.get('result_end_to_end_time', 'n/a')}",
                            flush=True,
                        )

    write_csv(csv_path, rows)
    print(f"Wrote {csv_path} and {jsonl_path}")
    return 0 if all(row.get("runner_status") == "ok" for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
