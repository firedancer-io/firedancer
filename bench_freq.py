#!/usr/bin/env python3
"""
Benchmark a program while monitoring CPU core frequency to observe
AVX-512 frequency scaling effects.

Usage:
    python3 bench_freq.py [--core CORE] [--poll-ms MS] [-- command args...]

Defaults:
    --core 0
    --poll-ms 5
    command: build/native/gcc/unit-test/test_reedsol
"""

import argparse
import os
import subprocess
import sys
import threading
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def read_freq_khz(core: int) -> int:
    """Read current frequency of a core in kHz from sysfs."""
    path = f"/sys/devices/system/cpu/cpu{core}/cpufreq/scaling_cur_freq"
    with open(path) as f:
        return int(f.read().strip())


def poll_frequency(core: int, interval_s: float, timestamps, freqs, stop_event):
    """Poll CPU frequency until stop_event is set."""
    t0 = time.monotonic()
    while not stop_event.is_set():
        try:
            freq = read_freq_khz(core)
        except (FileNotFoundError, PermissionError) as e:
            print(f"Warning: cannot read frequency for core {core}: {e}",
                  file=sys.stderr)
            break
        timestamps.append(time.monotonic() - t0)
        freqs.append(freq / 1000.0)  # convert kHz -> MHz
        time.sleep(interval_s)


def main():
    parser = argparse.ArgumentParser(
        description="Run a benchmark pinned to a core and plot CPU frequency")
    parser.add_argument("--core", type=int, default=0,
                        help="CPU core to pin the benchmark to (default: 0)")
    parser.add_argument("--poll-ms", type=float, default=5,
                        help="Frequency polling interval in ms (default: 5)")
    parser.add_argument("--warmup", type=float, default=0.5,
                        help="Seconds to record frequency before starting benchmark (default: 0.5)")
    parser.add_argument("--cooldown", type=float, default=1.0,
                        help="Seconds to record frequency after benchmark finishes (default: 1.0)")
    parser.add_argument("--output", type=str, default="freq_plot.png",
                        help="Output plot filename (default: freq_plot.png)")
    parser.add_argument("command", nargs="*",
                        default=["build/native/gcc/unit-test/test_reedsol"],
                        help="Command to benchmark (default: build/native/gcc/unit-test/test_reedsol)")

    args = parser.parse_args()
    core = args.core
    poll_interval = args.poll_ms / 1000.0
    cmd = args.command

    # Verify we can read frequency
    try:
        f0 = read_freq_khz(core)
        print(f"Core {core} current frequency: {f0/1000:.0f} MHz")
    except FileNotFoundError:
        sys.exit(f"Error: cannot read frequency for core {core}. "
                 "Check that cpufreq sysfs is available.")
    except PermissionError:
        sys.exit(f"Error: permission denied reading frequency for core {core}. "
                 "Try running with sudo.")

    timestamps = []
    freqs = []
    stop_event = threading.Event()

    # Start polling thread
    poller = threading.Thread(target=poll_frequency,
                              args=(core, poll_interval, timestamps, freqs, stop_event),
                              daemon=True)
    poller.start()

    # Warmup: let frequency stabilize and record baseline
    print(f"Recording baseline frequency for {args.warmup}s ...")
    time.sleep(args.warmup)
    bench_start = time.monotonic() - (timestamps[0] if timestamps else time.monotonic())
    # Adjust: bench_start is relative to our t0 in the poller
    bench_start_idx = len(timestamps)

    # Run benchmark pinned to the core
    taskset_cmd = ["taskset", "-c", str(core)] + cmd
    print(f"Running: {' '.join(taskset_cmd)}")
    t_start = time.monotonic()
    try:
        result = subprocess.run(taskset_cmd, capture_output=True, text=True)
    except FileNotFoundError:
        stop_event.set()
        poller.join()
        sys.exit(f"Error: command not found: {cmd[0]}")

    t_end = time.monotonic()
    bench_end_idx = len(timestamps)
    elapsed = t_end - t_start

    print(f"Benchmark finished in {elapsed:.2f}s (exit code {result.returncode})")
    if result.returncode != 0:
        print(f"stderr:\n{result.stderr[:500]}", file=sys.stderr)

    # Cooldown: record recovery
    print(f"Recording cooldown for {args.cooldown}s ...")
    time.sleep(args.cooldown)

    stop_event.set()
    poller.join()

    if not timestamps:
        sys.exit("Error: no frequency samples collected")

    # Compute stats
    if bench_start_idx < bench_end_idx:
        bench_freqs = freqs[bench_start_idx:bench_end_idx]
        if bench_freqs:
            avg = sum(bench_freqs) / len(bench_freqs)
            lo = min(bench_freqs)
            hi = max(bench_freqs)
            print(f"\nDuring benchmark: avg={avg:.0f} MHz, min={lo:.0f} MHz, max={hi:.0f} MHz")
            print(f"Samples collected: {len(timestamps)} total, {len(bench_freqs)} during benchmark")

    # Convert bench start/end to time coordinates
    if bench_start_idx < len(timestamps) and bench_end_idx <= len(timestamps):
        t_bench_start = timestamps[bench_start_idx]
        t_bench_end = timestamps[min(bench_end_idx, len(timestamps) - 1)]
    else:
        t_bench_start = t_bench_end = None

    # Plot
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.plot(timestamps, freqs, linewidth=0.8, color="tab:blue", label="Core frequency")

    if t_bench_start is not None:
        ax.axvspan(t_bench_start, t_bench_end, alpha=0.15, color="red",
                   label="Benchmark running")
        ax.axvline(t_bench_start, color="red", linestyle="--", linewidth=0.7)
        ax.axvline(t_bench_end, color="red", linestyle="--", linewidth=0.7)

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Frequency (MHz)")
    ax.set_title(f"CPU Core {core} Frequency During AVX-512 Benchmark\n({' '.join(cmd)})")
    ax.legend(loc="lower right")
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(args.output, dpi=150)
    print(f"\nPlot saved to {args.output}")


if __name__ == "__main__":
    main()
