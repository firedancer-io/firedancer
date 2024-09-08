#!/usr/bin/env python3

from collections import Counter
import sys

"""
usage: cat <log-file> | ./leak-detector.py 
"""

def main():
  line_cnt = 0 
  addr_map = dict()
  while True:
    try:
      line = sys.stdin.readline()
      line_cnt += 1
    except:
      continue
    if line == "":
      break
    if line.startswith("+++"):
      params = line[4:-1].split(":")
      backtrace_line_cnt = 0
      addr = ""
      if params[0] == "ALLOC":
        backtrace_line_cnt = int(params[1])
        addr = params[2]
      elif params[0] == "FREE":
        backtrace_line_cnt = int(params[1])
        addr = params[2]
      else:
        print("bad op")
        exit(1)
      backtrace_lines = ""
      for i in range(backtrace_line_cnt):
        while True:
          try:
            backtrace_lines += sys.stdin.readline()
            line_cnt += 1
            break
          except:
            print(line_cnt)
            
      if params[0] == "ALLOC":
        addr_map[addr] = (backtrace_lines, int(params[3]))
      elif params[0] == "FREE":
        if addr in addr_map:
          del addr_map[addr]
  bt_map_sz = Counter()
  bt_map_cnt = Counter()
  for addr in addr_map:
    bt_map_sz[addr_map[addr][0]] += addr_map[addr][1]
    bt_map_cnt[addr_map[addr][0]] += 1
    # print(addr)
    # print(addr_map[addr][0])

  for (bt, sz) in sorted(bt_map_sz.items(), key=lambda x: x[1]):
    print(sz, bt_map_cnt[bt])
    print(bt)

if __name__=="__main__": 
  main()