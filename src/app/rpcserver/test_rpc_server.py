import asyncio
import websockets
import requests
import json

url = 'http://localhost:8123/'

def good_method(arg):
    print(arg)
    x = requests.post(url,json=arg)
    res = json.loads(x.content)
    print(res)
    return res

def bad_method(arg):
    print(arg)
    x = requests.post(url,json=arg)
    res = x.content.decode('utf-8')
    print(res)
    assert res[0:5] == '<html'

bad_method({"jsonrpc":"2.0","id":1, "method":"notAMethod"})

res = good_method({"jsonrpc":"2.0","id":1, "method":"getSlot"})
slot = res['result']

res = good_method({"jsonrpc": "2.0","id":1, "method":"getBlock", "params": [slot, {"encoding": "json", "maxSupportedTransactionVersion":0, "transactionDetails":"full", "rewards":False}]})
for i in res['result']['transactions']:
    if 'Vote111111111111111111111111111111111111111' in i['transaction']['message']['accountKeys']:
        trans = i
        break
sig = trans['transaction']['signatures'][0]
accts = trans['transaction']['message']['accountKeys']

good_method({"jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": [sig, "json"]})

for acct in accts:
    good_method({ "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": [ acct, { "encoding": "base64" } ] })
    good_method({ "jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [ acct ] })

good_method({ "jsonrpc":"2.0","id":1, "method":"getBlockHeight" })

good_method({"jsonrpc": "2.0", "id": 1, "method": "getBlocks", "params": [slot-10, slot+10]})

good_method({"jsonrpc": "2.0", "id": 1, "method": "getBlocksWithLimit", "params": [slot-10, 20]})

good_method({"jsonrpc":"2.0","id":1,"method":"getBlockTime","params":[slot]})

good_method({"jsonrpc":"2.0","id":1, "method":"getEpochInfo"})

good_method({"jsonrpc":"2.0","id":1, "method":"getEpochSchedule"})

good_method({"jsonrpc":"2.0","id":1, "method":"getFirstAvailableBlock"})

good_method({"jsonrpc":"2.0","id":1, "method":"getGenesisHash"})

good_method({"jsonrpc":"2.0","id":1, "method":"getHealth"})

good_method({"jsonrpc":"2.0","id":1, "method":"getIdentity"})

good_method({"jsonrpc":"2.0","id":1, "method":"getLatestBlockhash"})

good_method({"jsonrpc":"2.0","id":1, "method":"getMaxShredInsertSlot"})

good_method({"jsonrpc": "2.0", "id": 1, "method": "getMinimumBalanceForRentExemption", "params": [50]})

good_method({"jsonrpc": "2.0", "id": 1, "method": "getMultipleAccounts", "params": [accts, {"encoding": "base64"}]})

good_method({"jsonrpc": "2.0", "id": 1, "method": "getSignatureStatuses", "params": [[sig, "4qj8WecUytFE96SFhdiTkc3v2AYLY7795sbSQTnYG7cPL9s6xKNHNyi3wraQc83PsNSgV8yedWbfGa4vRXfzBDzB"], {"searchTransactionHistory": True}]})

good_method({"jsonrpc":"2.0","id":1, "method":"getVersion"})

res = good_method({"jsonrpc": "2.0", "id": 1, "method": "getVoteAccounts", "params": [ ] })
votekeys = [ { "votePubkey": i['votePubkey'] } for i in res['result']['current'] ]

res = good_method({"jsonrpc": "2.0", "id": 1, "method": "getVoteAccounts", "params": votekeys[:3] })
assert len(res['result']['current']) == 3


print('Test passed!')
