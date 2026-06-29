#!/usr/bin/env python3
"""Decode and print the action sequence from an ipecho fuzzer input."""

import sys

ACTION_NAMES = ['CONNECT','DISCONNECT','SEND','READ','POLL','SHUTDOWN']
ACTION_CNT = 6
MAX_CLIENT_CNT = 256

def dump(data):
    if len(data) < 1:
        print("Input too short")
        return

    action_cnt = data[0]

    print(f"action_cnt         = {action_cnt}")
    print(f"total size         = {len(data)}")
    print()

    # Track client_fds state
    client_fds = [-1] * MAX_CLIENT_CNT

    cur = 1
    for i in range(action_cnt):
        if cur >= len(data):
            print(f"Action {i:2d}: OUT OF DATA at offset {cur}")
            break
        raw = data[cur]
        action = raw % ACTION_CNT
        name = ACTION_NAMES[action]

        if action == 0:  # CONNECT
            if cur+1 >= len(data):
                print(f"Action {i:2d} @{cur:3d}: {name} (truncated)")
                break
            idx = data[cur+1] % MAX_CLIENT_CNT
            old = client_fds[idx]
            print(f"Action {i:2d} @{cur:3d}: {name} idx={idx}  (slot was {'empty' if old==-1 else 'occupied=>skip'})")
            if old == -1:
                client_fds[idx] = 1  # mark as connected
            cur += 2

        elif action == 1:  # DISCONNECT
            if cur+1 >= len(data):
                print(f"Action {i:2d} @{cur:3d}: {name} (truncated)")
                break
            idx = data[cur+1] % MAX_CLIENT_CNT
            state = "has fd" if client_fds[idx] != -1 else "EMPTY=>skip"
            print(f"Action {i:2d} @{cur:3d}: {name} idx={idx}  ({state})")
            client_fds[idx] = -1
            cur += 2

        elif action == 2:  # SEND
            if cur+2 >= len(data):
                print(f"Action {i:2d} @{cur:3d}: {name} (truncated)")
                break
            idx = data[cur+1] % MAX_CLIENT_CNT
            send_sz = data[cur+2]
            state = "has fd" if client_fds[idx] != -1 else "EMPTY=>skip"
            payload = data[cur+3:cur+3+send_sz]
            print(f"Action {i:2d} @{cur:3d}: {name} idx={idx} sz={send_sz} ({state}) payload={payload.hex()}")
            cur += 3 + send_sz

        elif action == 3:  # READ
            if cur+2 >= len(data):
                print(f"Action {i:2d} @{cur:3d}: {name} (truncated)")
                break
            idx = data[cur+1] % MAX_CLIENT_CNT
            read_sz = data[cur+2] % 256
            state = "has fd" if client_fds[idx] != -1 else "EMPTY=>skip"
            print(f"Action {i:2d} @{cur:3d}: {name} idx={idx} sz={read_sz} ({state})")
            cur += 3

        elif action == 4:  # POLL
            print(f"Action {i:2d} @{cur:3d}: {name}")
            cur += 1

        elif action == 5:  # SHUTDOWN
            if cur+1 >= len(data):
                print(f"Action {i:2d} @{cur:3d}: {name} (truncated)")
                break
            idx = data[cur+1] % MAX_CLIENT_CNT
            state = "has fd" if client_fds[idx] != -1 else "EMPTY=>skip"
            print(f"Action {i:2d} @{cur:3d}: {name} idx={idx}  ({state})")
            cur += 2

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <fuzz-input-file>")
        print(f"   or: {sys.argv[0]} --hex 0x00,0x11,...")
        sys.exit(1)

    if sys.argv[1] == "--hex":
        hex_str = sys.argv[2]
        data = bytes(int(x, 16) for x in hex_str.split(","))
    else:
        with open(sys.argv[1], "rb") as f:
            data = f.read()

    dump(data)
