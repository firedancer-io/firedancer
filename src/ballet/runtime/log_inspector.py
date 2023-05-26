import argparse
from typing import Callable, Tuple
import re

class Breadcrumb:
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
               solana_filter: Callable[[str], bool],
               firedancer_filter: Callable[[str], bool],
               solana_identifier: Callable[[str], str],
               firedancer_identifier: Callable[[str], str],
               solana_display: Callable[[str], Tuple],
               firedancer_display: Callable[[str], Tuple]):
    self.id = str
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
      solana_filter=lambda log_line: "bank frozen" in log_line,
      firedancer_filter=lambda log_line: "bank_hash" in log_line,
      solana_identifier=lambda log_line: re.findall(r"bank frozen: (\d+)", log_line),
      firedancer_identifier=lambda log_line: re.findall(r"slot: (\d+)", log_line),
      solana_display=lambda log_line: re.findall(r"bank frozen: (\d+) hash: (\w+)", log_line),
      firedancer_display=lambda log_line: re.findall(r"slot: (\d+),  hash: (\w+)", log_line),
    ),
    "accounts_delta_hash": Breadcrumb( 
      solana_filter=lambda log_line: "hash_account_data_compare" in log_line,
      firedancer_filter=lambda log_line: "account_delta_hash_compare" in log_line,
      solana_identifier=lambda log_line: re.findall(r"pubkey: \((\w+)\) slot: \((\d+)\)", log_line),
      firedancer_identifier=lambda log_line: re.findall(r"pubkey: \((\w+)\) slot: \((\d+)\)", log_line),
      solana_display=lambda log_line: re.findall(r"pubkey: \((\w+)\) slot: \((\d+)\) lamports: \((\d+)\) owner: \((\w+)\) executable: \((\d+)\) rent_epoch: \((\d+)\) data_len: \((\d+)\) hash: \((\w+)\)", log_line),
      firedancer_display=lambda log_line: re.findall(r"pubkey: \((\w+)\) slot: \((\d+)\) lamports: \((\d+)\), owner: \((\w+)\), executable: \((\d+)\), rent_epoch: \((\d+)\), data_len: \((\d+)\), hash: \((\w+)\)", log_line),
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
          solana_results[tuple(breadcrumb.solana_identifier(line))] = breadcrumb.solana_display(line)

  # Read in Firedancer log file
  firedancer_results = {}
  with open(args.firedancer, 'r') as firedancer_log_file:
    for line in firedancer_log_file:
      for breadcrumb in breadcrumbs.values():
        if breadcrumb.firedancer_filter(line):
          firedancer_results[tuple(breadcrumb.firedancer_identifier(line))] = breadcrumb.firedancer_display(line)

  results = []
  for k in solana_results.keys():
    if k in firedancer_results:
      results.append(Result(solana_results[k], firedancer_results[k]))

  for result in results:
    match = result.solana_log_line == result.firedancer_log_line
    if match:
      continue
    print("##############################################################################################################################")
    print("")
    print("Solana:")
    print(result.solana_log_line)
    print("")
    print("Firedancer:")
    print(result.firedancer_log_line)
    print("")


if __name__ == "__main__":
  main()
