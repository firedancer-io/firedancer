#! /usr/bin/env python3

import requests
from datetime import datetime  
from datetime import timedelta  
import sys

DBGLVL = 0

def print_coming_leader_slots ( url, vid, show_cnt ):
    leader_slots = get_leader_schedule( url, vid )
    dt_now = datetime.now()
    (curr_slot_index, curr_absslot) = get_curr_slot( url )
    print(f"\n   Current slot:           {curr_slot_index:9d}         /         {curr_absslot:9d}        Current time: {dt_now}\n")
    for slot in leader_slots:
        if show_cnt < 1:
            break
        elif slot < curr_slot_index:
            continue
        else:
            show_cnt -= 1
            absslot = curr_absslot - curr_slot_index + slot
            delta_seconds = (slot - curr_slot_index)*0.4
            scheduled_time = dt_now + timedelta( seconds = delta_seconds )
            print(f"     Coming     slotIndex: {slot:9d}     absoluteSlot: {absslot:9d}       expected time: {scheduled_time}")
    print("");

def get_curr_slot( url ):
    epoch_info_json = get_epoch_info( url )
    return (epoch_info_json['result']['slotIndex'],epoch_info_json['result']['absoluteSlot']) if epoch_info_json else (0,0)

def get_epoch_info( url ):
    post_json = {"jsonrpc":"2.0","id":1, "method":"getEpochInfo"}
    req = requests.post(url, json=post_json)
    if DBGLVL > 0:
        print(f"status code: {req.status_code}")
        print(f"requ.json(): {req.json()}")
        print(f"req.json()['result']['slotIndex']: {req.json()['result']['slotIndex']}")
    # status code: 200
    # requ.json(): {
    #     'jsonrpc': '2.0', 
    #    'result': {
    #        'absoluteSlot': 211531410, 
    #        'blockHeight': 178575559, 
    #        'epoch': 502, 
    #        'slotIndex': 191154, 
    #        'slotsInEpoch': 432000, 
    #        'transactionCount': 267204575003
    #     }, 
    #    'id': 1
    # }
    # req.json()['result']['slotIndex']: 191154
    return req.json() if req.status_code == 200 else None

def get_leader_schedule( url, vid ):
    post_json = {"jsonrpc":"2.0","id":1, "method":"getLeaderSchedule"}
    req = requests.post(url, json=post_json)
    try:
        scheduled_slots = req.json()['result'][vid]
    except Exception as e: # vid is not in url corresponding mainnet_beta/devnet/testnet
        scheduled_slots = []
    if DBGLVL > 0:
        print(f"status code: {req.status_code}")
        print(f"requ.json(): {req.json()}")
        print(f"req.json()['result'][{vid}]: {scheduled_slots}")
    # status code: 200
    # requ.json(): {
    #     'jsonrpc': '2.0', 
    #    'result': {
    #        ...
    #        ,"Ft5fbkqNa76vnsjYNwjDZUXoTWpP7VYm3mtsaQckQADN":[
    #           312,
    #           313,
    #           314,
    #           315,
    #           636,
    #           637,
    #           638,
    #           639,
    #           824,
    #           825,
    #           826,
    #           827,
    #           1028,
    #           1029,
    #           1030,
    #           1031,
    #           1256,
    #           1257,
    #           ...,
    #           430054,
    #           430055,
    #           430500,
    #           430501,
    #           430502,
    #           430503,
    #           430688,
    #           430689,
    #           430690,
    #           430691,
    #           431080,
    #           431081,
    #           431082,
    #           431083,
    #           431368,
    #           431369,
    #           431370,
    #           431371
    #           ],...]
    #    }, 
    #    "id":1
    #  }
    # req.json()['result'][Ft5fbkqNa76vnsjYNwjDZUXoTWpP7VYm3mtsaQckQADN]: [312, 313, 314, 315, 636, 637, ..., 431081,431082,431083,431368,431369,431370,431371]
    return scheduled_slots if req.status_code == 200 else []


def main():
    vid      =     sys.argv[1]  if len(sys.argv) > 1 else f"Ft5fbkqNa76vnsjYNwjDZUXoTWpP7VYm3mtsaQckQADN"
    solnet   =     sys.argv[2]  if len(sys.argv) > 2 else "testnet" # choice of mainnet-beta, devnet, testnet
    show_cnt = int(sys.argv[3]) if len(sys.argv) > 3 and int(sys.argv[3]) > 20 else 20

    url = f"http://api.{solnet}.solana.com"
    # get_epoch_info(url)
    # get_leader_schedule(url, vid)
    print_coming_leader_slots ( url, vid, show_cnt )

if __name__ == "__main__":
    main()
