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


def read_traces_from_file(log_path):
    traces = []
    trace = []
    with open(log_path, 'r') as log_file:
        for raw_line in log_file:
            line = raw_line
            match = re.match(fast_trace_line_pattern, line)
            if len(traces) == 100:
                break
            if match is None:
                continue
            groups = match.groupdict()
            if groups["ic"] == "0" and len(trace) > 0:
                traces.append(trace)
                trace = []
            trace.append((raw_line.lstrip(), groups))

    return traces

def trace_stats(traces):
    instr_cnt = 0
    instr_type_counts = Counter()
    instr_type_pairs = Counter()
    for trace in traces:
        for (i, trace_ent) in enumerate(trace):
            instr_cnt += 1
            match = re.match(trace_line_pattern, trace_ent[0])
            groups = match.groupdict()

            instr_parts = groups["instr"].split(" ")
            instr_name = instr_parts[0]
            instr_src_mode = "unknown"
            if len(instr_parts) == 3 or len(instr_parts) == 4:
                if instr_parts[2][0] == "r":
                    instr_src_mode = "reg"
                else:
                    instr_src_mode = "imm"
            instr_type = instr_name + "_" + instr_src_mode
            instr_type_counts.update([instr_type])

            if i > 0:
                prev_trace_ent = trace[i-1]
                prev_match = re.match(trace_line_pattern, prev_trace_ent[0])
                prev_groups = prev_match.groupdict()

                prev_instr_parts = prev_groups["instr"].split(" ")
                prev_instr_name = prev_instr_parts[0]
                prev_instr_src_mode = "unknown"
                prev_instr_type = prev_instr_name + "_" + prev_instr_src_mode
                instr_type_pairs.update([(prev_instr_type, instr_type)])
        
    print("IC:", instr_cnt)
    for (instr_type, cnt) in instr_type_counts.most_common():
        print("ITC:", instr_type.ljust(20), str(cnt).ljust(8), cnt/instr_cnt)
    
    return
    print("ICP:", instr_cnt)
    for (instr_type, cnt) in instr_type_pairs.most_common():
        print("ITPC:", " ".join(instr_type).ljust(32), str(cnt).ljust(8), cnt/instr_cnt)

def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-f", "--fd-log-path", help="Path to Firedancer log file", required=True)
    args = arg_parser.parse_args()

    traces = read_traces_from_file(args.fd_log_path)
    print("FD traces:", len(traces))

    trace_stats(traces)

if __name__ == "__main__":
  main()
