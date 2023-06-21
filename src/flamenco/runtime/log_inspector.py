import argparse
import re
from typing import Callable, List, Tuple

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
    return (self.firedancer_filter(line) and fd_flag) or (self.solana_filter(line) and (not fd_flag))

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
    with open(file_location, 'r') as log_file:
      for line in log_file:
        for breadcrumb_name in breadcrumbs:
          breadcrumb = bakery[breadcrumb_name]
          if breadcrumb._filter(line, fd_flag):
            key = breadcrumb._extract_identifier(line, fd_flag)
            val = breadcrumb._extract_values(line, fd_flag)
            if val is None:
              continue
            results.setdefault(breadcrumb_name, dict()).setdefault(key, set()).add(val)
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
  solana_results = Breadcrumb.extract_log_line(file_location=args.solana, breadcrumbs=args.breadcrumbs, bakery=BAKERY, fd_flag=0)
  firedancer_results = Breadcrumb.extract_log_line(file_location=args.firedancer, breadcrumbs=args.breadcrumbs, bakery=BAKERY, fd_flag=1)
  for breadcrumb_name in args.breadcrumbs:
    print("##############################################################################################################################")
    print("results for " + breadcrumb_name)
    if breadcrumb_name not in solana_results:
      continue
    for key in solana_results[breadcrumb_name]:
      truth = solana_results[breadcrumb_name][key]
      reality = firedancer_results[breadcrumb_name].get(key, set())
      if len(reality) == 0 or len(truth - reality) == 0:
        continue
      print("----------------------------------------------------------------------------------------------------------------------------")
      print("identifier:", BAKERY[breadcrumb_name].identifiers)
      print("values:", BAKERY[breadcrumb_name].display_values)
      print("Solana:")
      for result in truth:
        print(result)
      print("Firedancer:")
      for result in reality:
        print(result)

if __name__ == "__main__":
  main()
