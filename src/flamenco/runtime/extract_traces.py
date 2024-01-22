import argparse
from collections import Counter
import re
from typing import Callable, List, Tuple
import difflib
import sys
import time
import multiprocessing
import os
import string

reg_val_pattern = lambda x: "(?P<r{}>[0-9A-F]{{16}})".format(x)

trace_line_pattern = "^\ *(?P<ic>\d+)\ \[{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}\]\ *(?P<pc>\d+): (?P<instr>[\w\ \,\-\+\_\[\]]+).*\n$".format(
    reg_val_pattern(0),
    reg_val_pattern(1),
    reg_val_pattern(2),
    reg_val_pattern(3),
    reg_val_pattern(4),
    reg_val_pattern(5),
    reg_val_pattern(6),
    reg_val_pattern(7),
    reg_val_pattern(8),
    reg_val_pattern(9),
    reg_val_pattern(10),
)

fast_trace_line_pattern = r"^\ *(?P<ic>\d+)\ \[.*\]\ *(?P<pc>\d+): .*\n$"

trace_start_line_pattern = r"^\ *0 "

trace_line_regex = re.compile(trace_line_pattern)

def read_traces_from_file(log_path, max_traces):
    traces = []
    trace = []
    dt = -time.time()
    dt2 = -time.time()
    with open(log_path, 'r') as log_file:
        print(file=sys.stderr)
        for line in log_file:
            match = re.match(fast_trace_line_pattern, line)
            if len(traces) == max_traces:
                break
            if match is None:
                continue
            groups = match.groupdict()
            if groups["ic"] == "0" and len(trace) > 0:
                dt2 += time.time()
                traces.append(trace)
                trace = []
                print("\rTraces:", len(traces), dt2, end="", file=sys.stderr)
                dt2 = -time.time()
            trace.append((line.lstrip(), groups))
    if len(trace) != 0:
        traces.append(trace)
    dt += time.time()
    print(file=sys.stderr)
    print("Trace time:", log_path, dt, len(traces), file=sys.stderr)
    return traces

def check_strict_match(fd_line, sl_line):
    fd_strict_match = re.match(trace_line_pattern, fd_line)
    sl_strict_match = re.match(trace_line_pattern, sl_line)
    checked_keys = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'ic']
    for checked_key in checked_keys:
        if fd_strict_match[checked_key] != sl_strict_match[checked_key]:
            return False
    return True

def traces_diff(fd_traces, sl_traces):
    used_sl_idxs = set()
    n_good_matches = 0

    for fd_idx, fd_trace in enumerate(fd_traces):
        best_n_matches = 0
        best_sl_idx = -1

        for sl_idx, sl_trace in enumerate(sl_traces):
            if sl_idx in used_sl_idxs:
                continue
            n_matches = 0
            for ((fd_line, fd_match), (sl_line, sl_match)) in zip(fd_trace, sl_trace):
                if int(fd_match["pc"]) == int(sl_match["pc"]):
                    if not check_strict_match(fd_line, sl_line):
                        break
                    n_matches += 1
                else:
                    break
            if n_matches > best_n_matches:
                best_n_matches = n_matches
                best_sl_idx = sl_idx
                
                if len(fd_trace) == len(sl_trace):
                    good_match = best_n_matches == len(fd_trace) and best_n_matches == len(sl_trace)
                    if good_match:
                        break

        if best_sl_idx == -1:
            print("NO MATCH:", fd_idx, flush=True)
            continue
        
        fd_lines = [x[0] for x in fd_traces[fd_idx]]
        sl_lines = [x[0] for x in sl_traces[best_sl_idx]]

        good_match = best_n_matches == len(fd_lines) and best_n_matches == len(sl_lines)
        
        if good_match:
            used_sl_idxs.add(best_sl_idx)
            n_good_matches += 1

        print("BEST MATCH: FD: {:<4} | SL: {:<4} | N_MATCHES: {:<6} | %_MATCH: {:<6.3f} | FD_LINES: {:<6} | SL_LINES: {:<6} | GOOD: {:<1} |".format(fd_idx, best_sl_idx, best_n_matches, best_n_matches / len(sl_lines), len(fd_lines), len(sl_lines), good_match), flush=True)

        with open("traces/fd_trace_{}.log".format(fd_idx), "w") as fd_trace_file:
            fd_trace_file.writelines(fd_lines)

        with open("traces/sl_trace_match_{}_{}.log".format(fd_idx, best_sl_idx), "w") as sl_trace_file:
            sl_trace_file.writelines(sl_lines)

        # sys.stdout.writelines(difflib.unified_diff(fd_lines, sl_lines))
        # print(len(list(difflib.unified_diff(fd_lines, sl_lines))))
    print("TOTAL_TRACES:", len(fd_traces))
    print("GOOD_MATCHES:", n_good_matches, n_good_matches / len(fd_traces))

def cache_sl(sl_traces):
    for i,trace in enumerate(sl_traces):
        with open(f'traces/sl_trace_{i}.log', 'w+') as f:
            f.write('\n'.join([x[0] for x in trace]))

def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-f", "--fd-log-path", help="Path to Firedancer log file", required=True)
    arg_parser.add_argument("-s", "--sl-log-path", help="Path to Solana log file", required=True)
    arg_parser.add_argument("-n", "--max-traces", help="Max number of traces to process", required=True, type=int)
    arg_parser.add_argument("-m", "--skip-traces", help="Number of traces to skip", required=False, default=0)
    args = arg_parser.parse_args()

    fd_traces = read_traces_from_file(args.fd_log_path, args.max_traces)
    print("FD traces:", len(fd_traces))
    sl_traces = read_traces_from_file(args.sl_log_path, args.max_traces)
    # cache_sl(sl_traces)
    print("SL traces:", len(sl_traces))

    traces_diff(fd_traces, sl_traces)

if __name__ == "__main__":
  main()