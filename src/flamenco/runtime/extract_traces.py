import argparse
from collections import Counter
import re
from typing import Callable, List, Tuple
import difflib
import sys
import time

reg_val_pattern = lambda x: "(?P<r{}>[0-9A-F]{{16}})".format(x)

trace_line_pattern = "^\ *(?P<ic>\d+)\ \[{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}\]\ *(?P<pc>\d+): (?P<instr>[\w\ \,\-\+\_\[\]]+)\n$".format(
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

trace_line_regex = re.compile(trace_line_pattern)

def read_traces_from_file(log_path):
    dt = -time.time()
    traces = []
    trace = []
    dt2 = 0.0
    dt3 = 0.0
    with open(log_path, 'r') as log_file:
        for raw_line in log_file:
            line = raw_line
            dt2 += -time.time()
            match = re.match(fast_trace_line_pattern, line)
            dt2 += time.time()
            if len(traces) == 5000:
                break
            if match is None:
                continue
            dt3 += -time.time()
            groups = match.groupdict()
            dt3 += time.time()
            if groups["ic"] == "0" and len(trace) > 0:
                traces.append(trace)
                trace = []
            trace.append((raw_line.lstrip(), groups))
    dt += time.time()
    print("DT", dt)
    print("DT2", dt2)
    print("DT3", dt3)

    return traces

def traces_diff(fd_traces, sl_traces):
    used_sl_idxs = []
    n_good_matches = 0

    for fd_idx, fd_trace in enumerate(fd_traces):
        best_n_matches = 0
        best_sl_idx = -1

        for sl_idx, sl_trace in enumerate(sl_traces):
            if sl_idx in used_sl_idxs:
                continue
            n_matches = 0
            for ((fd_line, fd_match), (sl_line, sl_match)) in zip(fd_trace, sl_trace):
                if fd_match["pc"] == sl_match["pc"]:
                    n_matches += 1
                else:
                    break
            if n_matches > best_n_matches:
                best_n_matches = n_matches
                best_sl_idx = sl_idx
                # print("NEW BEST:", fd_idx, sl_idx, n_matches)

        if best_sl_idx == -1:
            print("NO MATCH:", fd_idx)
            continue

        
        fd_lines = [x[0] for x in fd_traces[fd_idx]]
        sl_lines = [x[0] for x in sl_traces[best_sl_idx]]

        good_match = best_n_matches == len(fd_lines) and best_n_matches == len(sl_lines)
        
        if good_match:
            used_sl_idxs.append(best_sl_idx)
            n_good_matches += 1

        print("BEST MATCH: FD: {:>5}, SL: {:>5}, N_MATCHES: {:>8}, FD_LINES: {:>8}, SL_LINES: {:>8}, GOOD: {}".format(fd_idx, best_sl_idx, best_n_matches, len(fd_lines), len(sl_lines), good_match))

        with open("traces/fd_trace_{}.log".format(fd_idx), "w") as fd_trace_file:
            fd_trace_file.writelines(fd_lines)

        with open("traces/sl_trace_match_{}_{}.log".format(fd_idx, best_sl_idx), "w") as sl_trace_file:
            sl_trace_file.writelines(sl_lines)

        # sys.stdout.writelines(difflib.unified_diff(fd_lines, sl_lines))
        # print(len(list(difflib.unified_diff(fd_lines, sl_lines))))
    print("TOTAL_TRACES:", len(fd_traces))
    print("GOOD_MATCHES:", n_good_matches)

def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-f", "--fd-log-path", help="Path to Firedancer log file", required=True)
    arg_parser.add_argument("-s", "--sl-log-path", help="Path to Solana log file", required=True)
    args = arg_parser.parse_args()

    fd_traces = read_traces_from_file(args.fd_log_path)
    print("FD traces:", len(fd_traces))
    sl_traces = read_traces_from_file(args.sl_log_path)
    print("SL traces:", len(sl_traces))

    traces_diff(fd_traces, sl_traces)

if __name__ == "__main__":
  main()