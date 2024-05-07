import argparse
from pathlib import Path

def parse_logs(log_file_path):
    alloc_table = {}
    bt_table = {}
    bt_table.setdefault(0)
    with open(log_file_path, "r") as log_file:
        in_backtrace = False
        is_malloc = False
        backtrace = []
        addr = ""
        for line in log_file:
            if line.startswith("malloc"):
                addr = line[15:33]
                if addr in alloc_table:
                    print(f"double alloc: {addr}")
                backtrace = []
                in_backtrace = True
                is_malloc = True
            elif line.startswith("free"):
                addr = line[13:31]
                backtrace = []
                in_backtrace = True
                is_malloc = False
                if addr not in alloc_table:
                    print(f"unalloced free: {addr}")

            elif line.startswith("---"):
                in_backtrace = False
                if is_malloc:
                    alloc_table[addr] = backtrace
                else:
                    if addr in alloc_table:
                        del alloc_table[addr]
            if in_backtrace:
                if "NOTICE" in line:
                    continue
                backtrace.append(line)

    for addr in alloc_table:
        bt_str = "".join(alloc_table[addr][1:])
        if bt_str not in bt_table:
            bt_table[bt_str] = tuple([0, 0])
        sz = int(alloc_table[addr][0].split(" ")[-1])
        bt_table[bt_str] = tuple([bt_table[bt_str][0]+sz, bt_table[bt_str][1]+1])

    for (bt_str, stats) in bt_table.items():
        if stats is not None:
            print("SZ:", stats[0], "ALLOCS:", stats[1])
        else:
            print("NO STAT")
        print(bt_str)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--log-file",
        help="log file",
        type=Path,
    )
    args = parser.parse_args()
    parse_logs(args.log_file)
    

if __name__ == "__main__":
    main()
