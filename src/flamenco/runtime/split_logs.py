import sys

DIR = "./fd_logs/"
def flush(log_lines, idx):
    with open(DIR + "log_" + str(idx), 'w+') as file:
        file.write("".join(log_lines))

curr_log = []
curr_idx = -1
for line in sys.stdin:
    print(line, end="")
    if 'txn_idx' in line:
        if curr_idx != -1:
            flush(curr_log, curr_idx)
        curr_idx += 1
        curr_log = [line]
    # elif 'pass' in line or "ERR" in line:
    #     flush(curr_log, curr_idx)
    #     break
    else:
        curr_log.append(line)
