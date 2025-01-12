import requests
import argparse
import time

def get_txn_cnt(rpc: str):
  data="{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"getTransactionCount\",\"params\":[{\"commitment\":\"processed\"}]}"
  resp = requests.post(rpc, data=data, headers={"Content-Type": "application/json"})
  txn_cnt = resp.json()["result"]

  data="{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"getSlot\",\"params\":[{\"commitment\":\"processed\"}]}"
  resp = requests.post(rpc, data=data, headers={"Content-Type": "application/json"})
  slot = resp.json()["result"]
  return (txn_cnt, slot)

def get_cus_requested(metrics):
  resp = requests.get(metrics)
  lines = resp.text.splitlines()
  for line in lines:
    if line.startswith("pack_cus_net_sum"):
      return int(line.split(" ")[1])

def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser()
  parser.add_argument(
    "-r",
    "--rpc",
    required=True,
    type=str
  )
  parser.add_argument(
    "-m",
    "--metrics",
    required=True,
    type=str,
  )
  parser.add_argument(
    "-t",
    "--time",
    required=True,
    type=int
  )
  parser.add_argument(
    "-e",
    "--show-elapsed",
    action='store_true',
  )
  parser.add_argument(
    "-x",
    "--show-txns",
    action='store_true',
  )
  parser.add_argument(
    "-p",
    "--show-tps",
    action='store_true',
  )
  parser.add_argument(
    "-u",
    "--show-cus",
    action='store_true',
  )
  parser.add_argument(
    "-s",
    "--show-slot",
    action='store_true',
  )
  args = parser.parse_args()
  return args

def tps(rpc: str, metrics: str, poll: int, show_elapsed, show_txns, show_tps, show_cus, show_slot):
  while True:
    before_txn_cnt, slot0 = get_txn_cnt(rpc)
    before_cus = get_cus_requested(metrics)
    before_time = time.time()
    time.sleep(poll)
    after_time = time.time()
    after_txn_cnt, slot1 = get_txn_cnt(rpc)
    after_cus = get_cus_requested(metrics)
    txn_cnt_diff = int(after_txn_cnt - before_txn_cnt)
    time_diff = int(after_time - before_time)
    tps = int(txn_cnt_diff / time_diff)
    cus_diff = after_cus - before_cus
    cus_per_sec = int(cus_diff / time_diff)
    print(f"| ", end="")
    if show_slot:
      print(f"slot: {slot1} | ", end="")
    if show_elapsed:
      print(f"elapsed: {time_diff:>2} | ", end="")
    if show_txns:
      print(f"txns: {txn_cnt_diff:>10} | ", end="")
    if show_tps:
      print(f"tps: {tps:>10} | ", end="")
    if show_cus:
      print(f"cus/sec: {cus_per_sec:>10} | ", end="")
    print()

def main():
  args = parse_args()
  tps(args.rpc, args.metrics, args.time, args.show_elapsed, args.show_txns, args.show_tps, args.show_cus, args.show_slot )

if __name__ == "__main__":
  main()

