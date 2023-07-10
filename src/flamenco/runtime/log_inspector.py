import argparse
from collections import Counter
import re
from typing import Callable, List, Tuple

def str_list_to_hexdump(x):
  res0 = x[1:-1].split(", ")
  if res0[0] == '':
    return ""
  res1 = [int(y) for y in res0]
  res2 = ""
  
  for (i, z) in enumerate(res1):
    if i % 32 == 0:
      res2 += "\n  {}  ".format(hex(i)[2:].rjust(8, "0")) 
    elif i % 4 == 0:
      res2 += " "
    res2+=hex(z)[2:].rjust(2, "0")
  return res2

def display_firedancer_accounts_delta_hash_extra(log_line):
  res = re.findall(r"pubkey: (\w+), slot: (\d+), lamports: (\d+), owner: (\w+), executable: (\d+), rent_epoch: (\d+), data_len: (\d+), data: (\[[\d\s,]*\]) = (\w+)", log_line)[0]
  res2 = (res[0], res[1], res[2], res[3], res[4], res[5], res[6], str_list_to_hexdump(res[7]), res[8])
  return res2

def display_solana_accounts_delta_hash_extra(log_line):
  res = re.findall(r"pubkey: (\w+) slot: (\d+) lamports: (\d+)  owner: (\w+)  executable: (\w+),  rent_epoch: (\d+), data_len: (\d+), data: (\[[\d\s,]*\]) = (\w+)", log_line)[0]
  res2 = (res[0], res[1], res[2], res[3], res[4], res[5], res[6], str_list_to_hexdump(res[7]), res[8])
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
  def extract_log_line(file_location: str, breadcrumbs: List[str], bakery: dict, fd_flag: bool) -> dict:
    results = dict()
    with open(file_location, 'rb') as log_file:
      for (i, raw_line) in enumerate(log_file):
        line = raw_line.decode('utf-8')
        for breadcrumb_name in breadcrumbs:
          breadcrumb = bakery[breadcrumb_name]
          if breadcrumb._filter(line, fd_flag):
            key = breadcrumb._extract_identifier(line, fd_flag)
            val = breadcrumb._extract_values(line, fd_flag)
            if val is None:
              continue
            results.setdefault(breadcrumb_name, dict()).setdefault(key, Counter()).update([val])

    return results

def main():
  argParser = argparse.ArgumentParser()
  argParser.add_argument("-b", "--breadcrumbs", nargs='+', help="Breadcrumbs to display", required=True)
  argParser.add_argument("-f", "--firedancer", help="Path to Firedancer test-runtime log file", required=True)
  argParser.add_argument("-s", "--solana", help="Path to Solana validator log file", required=True)
  args = argParser.parse_args()

  # Define all breadcrumbs
  BAKERY = {
    "bank_hash": Breadcrumb(
      identifiers=("slot"),
      display_values=("hash"),
      solana_filter=lambda log_line: "bank frozen" in log_line,
      firedancer_filter=lambda log_line: "bank_hash" in log_line,
      solana_identifier=lambda log_line: re.findall(r"bank frozen: (\d+)", log_line),
      firedancer_identifier=lambda log_line: re.findall(r"slot: (\d+)", log_line),
      solana_display=lambda log_line: re.findall(r"bank frozen: (\d+) hash: (\w+)", log_line),
      firedancer_display=lambda log_line: re.findall(r"slot: (\d+),  hash: (\w+)", log_line),
    ),
    "accounts_delta_hash": Breadcrumb( 
      identifiers=("pubkey", "slot",),
      display_values=("pubkey", "slot", "fee", "lamports", "owner", "executable", "rent_epoch", "data_len", "hash"),
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
      solana_filter=lambda log_line: "hash_account_data:" in log_line,
      firedancer_filter=lambda log_line: "account_delta_hash " in log_line,
      solana_identifier=lambda log_line: re.findall(r"pubkey: (\w+) slot: (\d+)", log_line),
      firedancer_identifier=lambda log_line: re.findall(r"pubkey: (\w+), slot: (\d+)", log_line),
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
  firedancer_results = Breadcrumb.extract_log_line(file_location=args.firedancer, breadcrumbs=args.breadcrumbs, bakery=BAKERY, fd_flag=1)

  solana_results = Breadcrumb.extract_log_line(file_location=args.solana, breadcrumbs=args.breadcrumbs, bakery=BAKERY, fd_flag=0)

  for breadcrumb_name in args.breadcrumbs:
    print("##############################################################################################################################")
    print("results for " + breadcrumb_name)
    for key in solana_results[breadcrumb_name]:
      truth = solana_results[breadcrumb_name].get(key, Counter())
      reality = firedancer_results[breadcrumb_name].get(key, Counter())
      if len(reality) == 0 or len(truth - reality) == 0:
        continue
      print("----------------------------------------------------------------------------------------------------------------------------")
      print("identifier:", BAKERY[breadcrumb_name].identifiers)
      print("values:", BAKERY[breadcrumb_name].display_values)
      print("Solana: (total: {})".format(len(list(truth.elements()))))
      values = BAKERY[breadcrumb_name].display_values
      for result in truth:
        print("result: ")
        for res_key, res_value in zip(values, result):
          print("  {:<16}: {}".format(res_key, res_value))
        print("count: {:>5}".format(truth[result]))
      print()
      print("Firedancer: (total: {})".format(len(list(reality.elements()))))
      for result in reality:
        print("result: ")
        for res_key, res_value in zip(values, result):
          print("  {:<16}: {}".format(res_key, res_value))
        print("count: {:>5}".format(reality[result]))

if __name__ == "__main__":
  main()
