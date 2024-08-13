import requests
import time

api_endpoint = "http://api.testnet.solana.com"

# For a given epoch, get skip rate and skip rate adjusting for offline periods

json_data = {"jsonrpc":"2.0","id":1, "method":"getEpochInfo"}

fd_validator = "fdVa1oF2FtLq4b5T4HFxTjsgeWSCztDCqwxFegjYbZH"

response = requests.post(api_endpoint, json=json_data)
if response.status_code != 200:
    print("Error: " + response.text)
    exit()
epoch_json = response.json()['result']
print(epoch_json)

cur_epoch = epoch_json['epoch']
print("current epoch: "  + str(cur_epoch))

end_slot = epoch_json['absoluteSlot']
start_slot = end_slot - epoch_json['slotIndex']

# Get all leader slots for current epoch up to current slot
json_data =  {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getLeaderSchedule",
    "params": [
      {
        "identity": "fdVa1oF2FtLq4b5T4HFxTjsgeWSCztDCqwxFegjYbZH"
      }
    ]
}
print("posing request")
response = requests.post(api_endpoint, json=json_data)
print("done posting request")
leader_slots = response.json()['result']['fdVa1oF2FtLq4b5T4HFxTjsgeWSCztDCqwxFegjYbZH']
# Only consider slots that have happened
leader_slots = [slot + start_slot for slot in leader_slots if slot + start_slot < end_slot ]

# Figure out what slots were missed for whatever reason
missed_leaders = []
made_leaders = []
for slot in leader_slots:
    json_data = {
        "jsonrpc": "2.0", "id": 1,
        "method": "getBlock",
        "params": [
          slot, {"encoding": "jsonParsed", "transactionDetails" : "none" }
        ]
    }
    print("posting request")
    response = requests.post(api_endpoint, json=json_data)
    print("done posting request")
    print(response.json())
    while response.status_code != 200:
        print("enter")
        time.sleep(5)
        response = requests.post(api_endpoint, json=json_data)
    if "error" in response.json(): 
        missed_leaders.append(slot)
    else:
        made_leaders.append(slot)


print("Missed Leaders:")
print(missed_leaders)
print("Made Leaders:")
print(made_leaders)

# Now we have all of the leader slots that we missed. It's time to figure out
# which of them are from us being offline

true_skipped_slots = []
for slot in missed_leaders:
    for slot_check in [slot - 32, slot - 16, slot - 8, slot + 8, slot + 16, slot + 32]:
        json_data = { "jsonrpc": "2.0","id":1, "method":"getBlock", "params": [ slot_check, { "encoding": "json", "maxSupportedTransactionVersion":0, "transactionDetails":"accounts" } ] }
        response = requests.post(api_endpoint, json=json_data)
        if( "result" not in response.json()):
            print(response.json())
            if response.status_code in {413, 429}:
                print("waiting because of rate limit")
                time.sleep(5)
            continue

        transactions = response.json()["result"]["transactions"]
        acc_keys = set()
        for txn in transactions:
            for acc in txn["transaction"]["accountKeys"]:
                acc_keys.add(acc['pubkey'])
        if fd_validator in acc_keys:
            true_skipped_slots.append(slot)
            print("Slot " + str(slot) + " was actually skipped")
            break
    print("processed slot " + str(slot))



skip_rate = float(len(missed_leaders))/len(leader_slots)
adjusted_skip_rate = float(len(true_skipped_slots))/(len(made_leaders) + len(true_skipped_slots)) 

print("skip rate: " + str(skip_rate))
print("offline factored skip rate: " + str(adjusted_skip_rate))
print("made leaders count: " + str(len(made_leaders)))
print("true skipped leaders count: " + str(len(true_skipped_slots)))
print("true skipped slots: " + str(true_skipped_slots))
print("skipped slots: " + str(missed_leaders))
print("made leaders: " + str(made_leaders))    