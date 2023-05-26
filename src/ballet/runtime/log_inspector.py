import argparse
from typing import Callable, Tuple
import re

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

class Result:
  solana_log_line: str
  firedancer_log_line: str

  def __init__(self,
               solana_log_line: str,
               firedancer_log_line: str):
    self.solana_log_line = solana_log_line
    self.firedancer_log_line = firedancer_log_line

def main():
  argParser = argparse.ArgumentParser()
  argParser.add_argument("-b", "--breadcrumbs", nargs='+', help="Breadcrumbs to display", required=True)
  argParser.add_argument("-f", "--firedancer", help="Path to Firedancer test-runtime log file", required=True)
  argParser.add_argument("-s", "--solana", help="Path to Solana validator log file", required=True)
  args = argParser.parse_args()

  # Define all breadcrumbs
  all_breadcrumbs = {
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
    "calculate_fee": Breadcrumb(
      identifiers=("slot",),
      display_values=("slot", "fee", "prioirtizaiton_fee", "signature_fee", "write_lock_fee", "compute_fee", "congestion_multiplier"),
      solana_filter=lambda log_line: "calculate_fee_compare" in log_line,
      firedancer_filter=lambda log_line: "fd_runtime_calculate_fee_compare" in log_line,
      solana_identifier=lambda log_line: re.findall(r"slot\((\d+)\)", log_line),
      firedancer_identifier=lambda log_line: re.findall(r"slot=(\d+)", log_line),
      solana_display=lambda log_line: re.findall(r"slot\((\d+)\) invoked from\(\w+\) fee\((\d+)\) lamports_per_signature\(\d+\) tx_wide_compute_cap\(\d+\) support_set_\(\d+\) prioritization_fee\((\d+)\) signature_fee\((\d+)\) write_lock_fee\((\d+)\) compute_fee\((\d+)\) congestion_multiplier\((\d+)\)", log_line),
      firedancer_display=lambda log_line: re.findall(r"slot=(\d+) fee\((\d+).\d+\) = \(prioritization_fee\((\d+).\d+\) \+ signature_fee\((\d+).\d+\) \+ write_lock_fee\((\d+).\d+\) \+ compute_fee\((\d+).\d+\)\) \* congestion_multiplier\((\d+).\d+\)", log_line),
    )
  }

  # Filter only the breadcrumbs we are interested in
  breadcrumbs = {
    breadcrumb_name: breadcrumb for breadcrumb_name, breadcrumb in all_breadcrumbs.items() if breadcrumb_name in args.breadcrumbs
  }
  
  # Read in Solana log file
  solana_results = {}

  with open(args.solana, 'r', ) as solana_log_file:
    for line in solana_log_file:
      for breadcrumb in breadcrumbs.values():
        if breadcrumb.solana_filter(line):
          key = tuple(breadcrumb.solana_identifier(line))
          val = tuple(breadcrumb.solana_display(line))
          if len(val) == 0: continue
          val = val[0] if type(val[0]) == tuple else val

          if key in solana_results:
            solana_results[key].add(val)
          else:
            solana_results[key] = {val}


  # Read in Firedancer log file
  firedancer_results = {}
  with open(args.firedancer, 'r') as firedancer_log_file:
    for line in firedancer_log_file:
      for breadcrumb in breadcrumbs.values():
        if breadcrumb.firedancer_filter(line):
          key = tuple(breadcrumb.firedancer_identifier(line))
          val = tuple(breadcrumb.firedancer_display(line))
          if len(val) == 0: continue
          val = val[0] if type(val[0]) == tuple else val
          if key in firedancer_results:
            firedancer_results[key].add(val)
          else:
            firedancer_results[key] = {val}

  for k in solana_results.keys():
    if k in firedancer_results:
      diff = solana_results[k] - firedancer_results[k]
      if len(diff) == 0:
        continue
      print("##############################################################################################################################")
      print(breadcrumb.identifiers)
      print(breadcrumb.display_values)
      print("")
      print("Solana:")
      for result in solana_results[k]:
        print(result)
      print("")
      print("Firedancer:")
      for result in firedancer_results[k]:
        print(result)
      print("")


if __name__ == "__main__":
  main()
