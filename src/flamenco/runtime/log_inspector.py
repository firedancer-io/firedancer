import argparse
from collections import Counter
import re
from typing import Callable, List, Tuple
import difflib
import sys
import multiprocessing

def str_list_to_hexdump(x):
  res0 = x[1:-1].split(", ")
  if res0[0] == "":
    return ""
  res2 = ""

  for (i, z_str) in enumerate(res0):
    z = int(z_str)
    if i % 32 == 0:
      res2 += "\n  {}  ".format(hex(i)[2:].rjust(8, "0"))
    elif i % 16 == 0:
      res2 += "  "
    elif i % 4 == 0:
      res2 += " "
    res2+=hex(z)[2:].rjust(2, "0")
  return res2

def hex_to_hexdump(x):
  if len(x) == 0:
    return ""
  # res0 = bytes.fromhex(x)

  res2 = ""
  for i in range(0, len(x), 64):
    res2 += "\n  {:0>8x}  {} {} {} {}  {} {} {} {}".format(i//2, 
        x[i:i+8], x[i+8:i+16], x[i+16:i+24], x[i+24:i+32],
        x[i+32:i+40], x[i+40:i+48], x[i+48:i+56], x[i+56:i+64])
  return res2.rstrip()

def display_firedancer_accounts_delta_hash_extra(log_line):
  # print(log_line)
  res = re.findall(r"pubkey: (\w+), slot: \((\d+)\), lamports: (\d+), owner: (\w+), executable: (\d+), rent_epoch: (\d+), data_len: (\d+), data: (\[[\d\s,]*\]) = (\w+)", log_line)[0]
  res2 = [res[0], res[1], res[2], res[3], res[4], res[5], res[6], str_list_to_hexdump(res[7]), res[8]]
  return res2

def display_solana_accounts_delta_hash_extra(log_line):
  # print(log_line)
  # res = re.findall(r"pubkey: \((\w+)\) slot: \((\d+)\) lamports: \((\d+)\) owner: \((\w+)\) executable: \((\d+)\) rent_epoch: \((\d+)\) data_len: \((\d+)\) hash: \((\w+)\) data: \(([0-9a-f]*)\)", log_line)[0]
  # res = re.findall(r"pubkey: \((\w+)\) slot: \((\d+)\) include_slot: \(true\)  lamports: \((\d+)\) owner: \((\w+)\) executable: \((\d+)\) rent_epoch: \((\d+)\) data_len: \((\d+)\) hash: \((\w+)\) includedata: \(([0-9a-f]*)\)", log_line)[0]
  res = re.findall(r"pubkey: \((\w+)\) slot: \((\d+)\) lamports: \((\d+)\) owner: \((\w+)\) executable: \((\d+)\) rent_epoch: \((\d+)\) data_len: \((\d+)\) hash: \((\w+)\) data: \(([0-9a-f]*)\)", log_line)[0]
  executable = "0"
  if res[4] == 1:
    executable = "1"

  # res2 = [res[0], res[1], res[2], res[3], executable, res[5], res[6], hex_to_hexdump(res[8]), res[7]]
  res2 = [res[0], res[1], res[2], res[3], executable, res[5], res[6], hex_to_hexdump(res[8]), res[7]]
  return res2

# print(str_list_to_hexdump('[1, 0, 0, 0, 6, 161, 236, 95, 109, 61, 176, 220, 100, 179, 152, 185, 127, 63, 240, 170, 166, 42, 118, 100, 242, 252, 76, 158, 148, 232, 138, 73, 102, 133, 73, 252, 234, 0, 182, 30, 163, 194, 135, 42, 246, 107, 91, 234, 12, 251, 211, 132, 101, 37, 231, 81, 74, 152, 183, 1, 206, 99, 188, 189, 73, 253, 58, 170, 7, 31, 0, 0, 0, 0, 0, 0, 0, 207, 28, 175, 10, 0, 0, 0, 0, 31, 0, 0, 0, 208, 28, 175, 10, 0, 0, 0, 0, 30, 0, 0, 0, 209, 28, 175, 10, 0, 0, 0, 0, 29, 0, 0, 0, 210, 28, 175, 10, 0, 0, 0, 0, 28, 0, 0, 0, 211, 28, 175, 10, 0, 0, 0, 0, 27, 0, 0, 0, 212, 28, 175, 10, 0, 0, 0, 0, 26, 0, 0, 0, 213, 28, 175, 10, 0]'))

class Breadcrumb:
  identifiers: tuple
  display_values: tuple
  # Filters instances of this breadcrumb in the Solana validator log file
  solana_filter: Callable[[str], bool]
  # Filters instances of this breadcrumb in the Firedancer test runtime log file
  firedancer_filter: Callable[[str], bool]
  # Extracts a tuple uniquely identifying instances of this breadcrumb in the Solana validator log file
  solana_identifier: Callable[[str], Tuple]
  # Extracts a tuple uniquely identifying instances of this breadcrumb in the Firedancer test runtime log file
  firedancer_identifier: Callable[[str], Tuple]
  # Pretty-print the Solana log line for inspection
  solana_display: Callable[[str], Tuple]
  # Pretty-print the Firedancer log line for inspection
  firedancer_display: Callable[[str], Tuple]

  def __init__(self,
               identifiers: tuple,
               display_values: tuple,
               solana_filter: Callable[[str], bool],
               firedancer_filter: Callable[[str], bool],
               solana_identifier: Callable[[str], str],
               firedancer_identifier: Callable[[str], str],
               solana_display: Callable[[str], Tuple],
               firedancer_display: Callable[[str], Tuple]):
    self.id = str
    self.identifiers = identifiers
    self.display_values = display_values
    self.solana_filter = solana_filter
    self.firedancer_filter = firedancer_filter
    self.solana_identifier = solana_identifier
    self.firedancer_identifier = firedancer_identifier
    self.solana_display = solana_display
    self.firedancer_display = firedancer_display

  def _filter(self, line: str, fd_flag: bool) -> bool:
    if fd_flag:
      return self.firedancer_filter(line)
    else:
      return self.solana_filter(line)

  def _extract_values(self, line: str, fd_flag: bool):
    val = tuple(self.firedancer_display(line)) if fd_flag else tuple(self.solana_display(line))
    if len(val) == 0:
      return None
    return val[0] if type(val[0]) == tuple else val

  def _extract_identifier(self, line: str, fd_flag: bool) -> str:
    return tuple(self.firedancer_identifier(line)) if fd_flag else tuple(self.solana_identifier(line))

  @staticmethod
  def extract_log_line(file_location: str, breadcrumbs: List[str], bakery: dict, fd_flag: bool, check_last_flag: bool, pattern) -> dict:
    results = dict()
  
    for breadcrumb_name in breadcrumbs:
      results.setdefault(breadcrumb_name, dict())
    for breadcrumb_name in breadcrumbs:
      breadcrumb_results = results[breadcrumb_name]
      breadcrumb = bakery[breadcrumb_name]
      with open(file_location, 'r') as log_file:
        breadcrumb_lines = dict()
        for (i, line) in enumerate(log_file):
          if i % 100_000 == 0:
            print("Filtering: Line:", i, breadcrumb_name, len(breadcrumb_lines), flush=True, file=sys.stderr)
          if pattern and pattern not in line:
            continue
          if breadcrumb._filter(line, fd_flag):
            key = breadcrumb._extract_identifier(line, fd_flag)
            if check_last_flag:
              breadcrumb_lines[key] = line
            else:
              breadcrumb_lines.setdefault(key, list()).append(line)

        for (i, key) in enumerate(breadcrumb_lines):
          if i % 10_000 == 0:
            print("Evaluating: Line:", i, breadcrumb_name, len(results[breadcrumb_name]), flush=True, file=sys.stderr)
          if check_last_flag:
            line = breadcrumb_lines[key]
            val = breadcrumb._extract_values(line, fd_flag)
            breadcrumb_results[key] = Counter([val])
          else:
            res = breadcrumb_results[key].setdefault(key, Counter())
            lines = breadcrumb_lines[key]
            for line in lines:
              val = breadcrumb._extract_values(line, fd_flag)
              if val is None:
                continue 
              res.update([val])

    return results

def main():
  argParser = argparse.ArgumentParser()
  argParser.add_argument("-b", "--breadcrumbs", nargs='+', help="Breadcrumbs to display", required=True)
  argParser.add_argument("-f", "--firedancer", help="Path to Firedancer test-runtime log file", required=True)
  argParser.add_argument("-s", "--solana", help="Path to Solana validator log file", required=True)
  argParser.add_argument("-c", "--check-last", help="Only check last from solana against firedancer", action="store_true")
  argParser.add_argument("-d", "--diff", help="Print info diff", action="store_true")
  argParser.add_argument("-q", "--hide-full", help="Hide full output", action="store_true")
  argParser.add_argument("-x", "--pattern", help="Check for pattern in lines", default=None)
  args = argParser.parse_args()

  # Define all breadcrumbs
  BAKERY = {
    "bank_hash": Breadcrumb(
      identifiers=("slot"),
      display_values=("slot", "hash"),
      solana_filter=lambda log_line: "bank frozen" in log_line,
      firedancer_filter=lambda log_line: "bank_hash" in log_line,
      solana_identifier=lambda log_line: re.findall(r"bank frozen: (\d+)", log_line),
      firedancer_identifier=lambda log_line: re.findall(r"slot: (\d+)", log_line),
      solana_display=lambda log_line: re.findall(r"bank frozen: (\d+) hash: (\w+)", log_line),
      firedancer_display=lambda log_line: re.findall(r"slot: (\d+),  hash: (\w+)", log_line),
    ),
    "accounts_delta_hash": Breadcrumb(
      identifiers=("pubkey", "slot",),
      display_values=("pubkey", "slot", "lamports", "owner", "executable", "rent_epoch", "data_len", "hash"),
      solana_filter=lambda log_line: "hash_account_data_compare" in log_line,
      firedancer_filter=lambda log_line: "account_delta_hash_compare" in log_line,
      solana_identifier=lambda log_line: re.findall(r"pubkey: \((\w+)\) slot: \((\d+)\)", log_line),
      firedancer_identifier=lambda log_line: re.findall(r"pubkey: \((\w+)\) slot: \((\d+)\)", log_line),
      solana_display=lambda log_line: re.findall(r"pubkey: \((\w+)\) slot: \((\d+)\) lamports: \((\d+)\) owner: \((\w+)\) executable: \((\d+)\) rent_epoch: \((\d+)\) data_len: \((\d+)\) hash: \((\w+)\)", log_line),
      firedancer_display=lambda log_line: re.findall(r"pubkey: \((\w+)\) slot: \((\d+)\) lamports: \((\d+)\), owner: \((\w+)\), executable: \((\d+)\), rent_epoch: \((\d+)\), data_len: \((\d+)\), hash: \((\w+)\)", log_line),
    ),
    "accounts_delta_hash_extra": Breadcrumb(
      identifiers=("pubkey", "slot",),
      display_values=("pubkey", "slot", "lamports", "owner", "executable", "rent_epoch", "data_len", "data", "hash"),
      solana_filter=lambda log_line: "hash_account_data" in log_line,
      firedancer_filter=lambda log_line: "account_delta_hash " in log_line,
      solana_identifier=lambda log_line: re.findall(r"pubkey: \((\w+)\) slot: \((\d+)\)", log_line),
      firedancer_identifier=lambda log_line: re.findall(r"pubkey: (\w+), slot: \((\d+)\)", log_line),
      solana_display=display_solana_accounts_delta_hash_extra,
      firedancer_display=display_firedancer_accounts_delta_hash_extra,
    ),
    "calculate_fee": Breadcrumb(
      identifiers=("slot",),
      display_values=("slot", "fee", "prioirtizaiton_fee", "signature_fee", "write_lock_fee", "compute_fee", "congestion_multiplier"),
      solana_filter=lambda log_line: "calculate_fee_compare" in log_line,
      firedancer_filter=lambda log_line: "fd_runtime_calculate_fee_compare" in log_line,
      solana_identifier=lambda log_line: re.findall(r"slot\((\d+)\)", log_line),
      firedancer_identifier=lambda log_line: re.findall(r"slot=(\d+)", log_line),
      solana_display=lambda log_line: re.findall(r"slot\((\d+)\) invoked from\(\w+\) fee\((\d+)\) lamports_per_signature\(\d+\) support_set_\(\d+\) prioritization_fee\((\d+)\) signature_fee\((\d+)\) write_lock_fee\((\d+)\) compute_fee\((\d+)\) congestion_multiplier\((\d+)\)", log_line),
      firedancer_display=lambda log_line: re.findall(r"slot=(\d+) fee\((\d+).\d+\) = \(prioritization_fee\((\d+).\d+\) \+ signature_fee\((\d+).\d+\) \+ write_lock_fee\((\d+).\d+\) \+ compute_fee\((\d+).\d+\)\) \* congestion_multiplier\((\d+).\d+\)", log_line),
    )
  }

  # Read in Solana log file
  print("Extracting Solana logs...", flush=True, file=sys.stderr)
  solana_results = Breadcrumb.extract_log_line(file_location=args.solana, breadcrumbs=args.breadcrumbs, bakery=BAKERY, fd_flag=0, check_last_flag=args.check_last, pattern=args.pattern)
  print("Done:", flush=True, file=sys.stderr)
  for key in solana_results:
    print(" ", key, len(solana_results[key]), flush=True, file=sys.stderr)

  print("Extracting Firedancer logs...", flush=True, file=sys.stderr)
  firedancer_results = Breadcrumb.extract_log_line(file_location=args.firedancer, breadcrumbs=args.breadcrumbs, bakery=BAKERY, fd_flag=1, check_last_flag=args.check_last, pattern=args.pattern)
  print("Done:", flush=True, file=sys.stderr)
  for key in firedancer_results:
    print(" ", key, len(firedancer_results[key]), flush=True, file=sys.stderr)


  for breadcrumb_name in args.breadcrumbs:
    print("##############################################################################################################################")
    print("results for " + breadcrumb_name)
    total_diffs = 0
    for key in solana_results[breadcrumb_name]:
      truth_pre = solana_results[breadcrumb_name].get(key, Counter())
      truth = truth_pre
      if args.check_last:
        truth = Counter([list(truth.elements())[-1]])
      reality = firedancer_results[breadcrumb_name].get(key, Counter())
      if len(truth - reality) == 0:
        continue
      total_diffs += 1
      print("----------------------------------------------------------------------------------------------------------------------------")
      print("identifier:", BAKERY[breadcrumb_name].identifiers)
      print("values:", BAKERY[breadcrumb_name].display_values)
      print("Solana: (total: {})".format(len(list(truth_pre.elements()))))
      values = BAKERY[breadcrumb_name].display_values

      if args.hide_full:
        for (ident_key, ident_val) in zip(BAKERY[breadcrumb_name].identifiers, key[0]):
          print("{:<16}: {}".format(ident_key, ident_val))

      truth_strs =[]
      reality_strs = []

      for result in truth:
        if not args.hide_full:
          print("result: ")
        for res_key, res_value in zip(values, result):
          truth_str = "{:<16}: {}\n".format(res_key, res_value)
          truth_strs.extend(truth_str.splitlines(keepends=True))
          if not args.hide_full:
            print("  {}".format(truth_str), end="")
        count_str = "count: {:>5}\n".format(truth[result])
        truth_strs.extend(count_str.splitlines(keepends=True))
        if not args.hide_full:
          print(count_str, end="")

      print()

      print("Firedancer: (total: {})".format(len(list(reality.elements()))))
      for result in reality:
        if not args.hide_full:
          print("result: ")
        for res_key, res_value in zip(values, result):
          reality_str = "{:<16}: {}\n".format(res_key, res_value)
          reality_strs.extend(reality_str.splitlines(keepends=True))
          if not args.hide_full:
            print("  {}".format(reality_str), end="")
        count_str = "count: {:>5}\n".format(reality[result])
        reality_strs.extend(count_str.splitlines(keepends=True))
        if not args.hide_full:
          print(count_str, end="")

      if args.diff:
        print()
        print("Diff: ")
        diff = difflib.unified_diff(truth_strs, reality_strs, fromfile="Solana", tofile="Firedancer")
        sys.stdout.writelines(diff)

    for key in firedancer_results[breadcrumb_name]:
      truth_pre = firedancer_results[breadcrumb_name].get(key, Counter())
      truth = truth_pre
      if args.check_last:
        truth = Counter([list(truth.elements())[-1]])
      reality = solana_results[breadcrumb_name].get(key, Counter())
      if len(truth - reality) == 0:
        continue
      total_diffs += 1
      print("----------------------------------------------------------------------------------------------------------------------------")
      print("identifier:", BAKERY[breadcrumb_name].identifiers)
      print("values:", BAKERY[breadcrumb_name].display_values)
      print("Firedancer: (total: {})".format(len(list(truth_pre.elements()))))
      values = BAKERY[breadcrumb_name].display_values

      if args.hide_full:
        for (ident_key, ident_val) in zip(BAKERY[breadcrumb_name].identifiers, key[0]):
          print("{:<16}: {}".format(ident_key, ident_val))

      truth_strs =[]
      reality_strs = []

      for result in truth:
        if not args.hide_full:
          print("result: ")
        for res_key, res_value in zip(values, result):
          truth_str = "{:<16}: {}\n".format(res_key, res_value)
          truth_strs.extend(truth_str.splitlines(keepends=True))
          if not args.hide_full:
            print("  {}".format(truth_str), end="")
        count_str = "count: {:>5}\n".format(truth[result])
        truth_strs.extend(count_str.splitlines(keepends=True))
        if not args.hide_full:
          print(count_str, end="")

      print()

      print("Solana: (total: {})".format(len(list(reality.elements()))))
      for result in reality:
        if not args.hide_full:
          print("result: ")
        for res_key, res_value in zip(values, result):
          reality_str = "{:<16}: {}\n".format(res_key, res_value)
          reality_strs.extend(reality_str.splitlines(keepends=True))
          if not args.hide_full:
            print("  {}".format(reality_str), end="")
        count_str = "count: {:>5}\n".format(reality[result])
        reality_strs.extend(count_str.splitlines(keepends=True))
        if not args.hide_full:
          print(count_str, end="")

      if args.diff:
        print()
        print("Diff: ")
        diff = difflib.unified_diff(reality_strs, truth_strs, fromfile="Solana", tofile="Firedancer")
        sys.stdout.writelines(diff)

    print("----------------------------------------------------------------------------------------------------------------------------")
    print("total results:", total_diffs)

if __name__ == "__main__":
  main()