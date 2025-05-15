import asyncio
import websockets
import requests
import json
import argparse
import random

parser = argparse.ArgumentParser(
    prog='test_rpc_server',
    description='Unit test/fuzzer for rpcserver')
parser.add_argument('-u', '--url', default='http://localhost:8123/')
parser.add_argument('-f', '--fuzz', action='store_true', default=False)
args = parser.parse_args()
url=args.url
fuzz=args.fuzz

fixtures = []

def good_method(arg):
    print('GOOD: ' + json.dumps(arg))
    data = json.dumps(arg).encode('utf-8')
    if fuzz:
        fixtures.append(data)
    x = requests.post(url,headers={'Content-Type':'application/json'},data=data)
    with open('response','wb') as fd:
        fd.write(x.content)
    res = json.loads(x.content)
    print(res)
    assert arg['id'] == res['id']
    return res

def bad_method(arg):
    print("BAD: " + json.dumps(arg))
    data = json.dumps(arg).encode('utf-8')
    if fuzz:
        fixtures.append(data)
    x = requests.post(url,headers={'Content-Type':'application/json'},data=data)
    with open('response','bw') as fd:
        fd.write(x.content)
    res = json.loads(x.content)
    print(res)
    assert res['error'] is not None

bad_method({"jsonrpc":"2.0","id":1, "method":"notAMethod"})

res = good_method({"jsonrpc":"2.0","id":1, "method":"getSlot"})
slot = res['result']
bad_method({"id":1, "method":"getSlot"})
bad_method({"jsonrpc":"1.0","id":1, "method":"getSlot"})
bad_method({"jsonrpc":"2.0", "method":"getSlot"})
bad_method({"jsonrpc":"2.0","id":1})
bad_method({"jsonrpc":"2.0","idx":1, "method":"getSlot"})

res = good_method({"jsonrpc":"2.0","id":"abc", "method":"getSlot"})

res = good_method({"jsonrpc": "2.0","id":1, "method":"getBlock", "params": [slot, {"encoding": "json", "maxSupportedTransactionVersion":0, "transactionDetails":"full", "rewards":False}]})
for i in res['result']['transactions']:
    if 'Vote111111111111111111111111111111111111111' in i['transaction']['message']['accountKeys']:
        trans = i
        break
sig = trans['transaction']['signatures'][0]
accts = trans['transaction']['message']['accountKeys']

bad_method({"jsonrpc": "2.0","id":1, "method":"getBlock", "params": [{"encoding": "json", "maxSupportedTransactionVersion":0, "transactionDetails":"full", "rewards":False}]})
bad_method({"jsonrpc": "2.0","id":1, "method":"getBlock", "params": [slot, {"encoding": "jsonx", "maxSupportedTransactionVersion":0, "transactionDetails":"full", "rewards":False}]})
bad_method({"jsonrpc": "2.0","id":1, "method":"getBlock", "params": [slot, {"encoding": "json", "maxSupportedTransactionVersion":0, "transactionDetails":"fullx", "rewards":False}]})
bad_method({"jsonrpc": "2.0","id":1, "method":"getBlock", "params": [999999999, {"encoding": "json", "maxSupportedTransactionVersion":0, "transactionDetails":"full", "rewards":False}]})

good_method({"jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": [sig, "json"]})
good_method({"jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": [sig, {"encoding":"json"}]})
good_method({"jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": [sig, {"encoding":"json","commitment":"finalized"}]})
bad_method({"jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": [1234]})
bad_method({"jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": [sig, "jsonx"]})
bad_method({"jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": [sig, {"encoding":"json","commitment":"finalizedx"}]})

for acct in accts:
    good_method({ "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": [ acct, { "encoding": "base64" } ] })
    good_method({ "jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [ acct ] })

    bad_method({ "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": [ { "encoding": "base64" } ] })
    bad_method({ "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": [ "012345", { "encoding": "base64" } ] })
    bad_method({ "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": [ acct, { "encoding": "base64x" } ] })

    bad_method({ "jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [ ] })
    bad_method({ "jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [ "012345" ] })

good_method({ "jsonrpc":"2.0","id":1, "method":"getBlockHeight" })

good_method({"jsonrpc": "2.0", "id": 1, "method": "getBlocks", "params": [slot-10, slot+10]})
bad_method({"jsonrpc": "2.0", "id": 1, "method": "getBlocks", "params": []})
bad_method({"jsonrpc": "2.0", "id": 1, "method": "getBlocks", "params": ["slot-10", slot+10]})

good_method({"jsonrpc": "2.0", "id": 1, "method": "getBlocksWithLimit", "params": [slot-10, 20]})
bad_method({"jsonrpc": "2.0", "id": 1, "method": "getBlocksWithLimit", "params": []})
bad_method({"jsonrpc": "2.0", "id": 1, "method": "getBlocksWithLimit", "params": [slot-10]})
bad_method({"jsonrpc": "2.0", "id": 1, "method": "getBlocksWithLimit", "params": ["slot-10", 20]})

good_method({"jsonrpc":"2.0","id":1,"method":"getBlockTime","params":[slot]})
bad_method({"jsonrpc":"2.0","id":1,"method":"getBlockTime","params":[]})
bad_method({"jsonrpc":"2.0","id":1,"method":"getBlockTime","params":["slot"]})
bad_method({"jsonrpc":"2.0","id":1,"method":"getBlockTime","params":[999999999]})

good_method({"jsonrpc":"2.0","id":1, "method":"getEpochInfo"})

good_method({"jsonrpc":"2.0","id":1, "method":"getEpochSchedule"})

good_method({ "id":1, "jsonrpc":"2.0", "method":"getFeeForMessage", "params":["AQABAgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQAA", { "commitment":"processed" }]})
bad_method({ "id":1, "jsonrpc":"2.0", "method":"getFeeForMessage", "params":[{ "commitment":"processed" }]})
bad_method({ "id":1, "jsonrpc":"2.0", "method":"getFeeForMessage", "params":["\x0001AQABAgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQAA", { "commitment":"processed" }]})

good_method({"jsonrpc":"2.0","id":1, "method":"getFirstAvailableBlock"})

good_method({"jsonrpc":"2.0","id":1, "method":"getGenesisHash"})

good_method({"jsonrpc":"2.0","id":1, "method":"getHealth"})

good_method({"jsonrpc":"2.0","id":1, "method":"getIdentity"})

res = good_method({"jsonrpc":"2.0","id":1, "method":"getLatestBlockhash"})
hash = res['result']['value']['blockhash']
res = good_method({"jsonrpc":"2.0","id":1, "method":"isBlockhashValid", "params": [hash]})
assert bool(res['result']['value'])
bad_method({"jsonrpc":"2.0","id":1, "method":"isBlockhashValid", "params": []})
bad_method({"jsonrpc":"2.0","id":1, "method":"isBlockhashValid", "params": ["01234"]})

good_method({"jsonrpc":"2.0","id":1, "method":"getMaxShredInsertSlot"})

good_method({"jsonrpc": "2.0", "id": 1, "method": "getMinimumBalanceForRentExemption", "params": [50]})

good_method({"jsonrpc": "2.0", "id": 1, "method": "getMultipleAccounts", "params": [accts, {"encoding": "base64"}]})
bad_method({"jsonrpc": "2.0", "id": 1, "method": "getMultipleAccounts", "params": [accts, {"encoding": "base64x"}]})
bad_method({"jsonrpc": "2.0", "id": 1, "method": "getMultipleAccounts", "params": [["012345"], {"encoding": "base64"}]})

good_method({"jsonrpc": "2.0", "id": 1, "method": "getSignatureStatuses", "params": [[sig, "4qj8WecUytFE96SFhdiTkc3v2AYLY7795sbSQTnYG7cPL9s6xKNHNyi3wraQc83PsNSgV8yedWbfGa4vRXfzBDzB"], {"searchTransactionHistory": True}]})

good_method({"jsonrpc":"2.0","id":1, "method":"getVersion"})

res = good_method({"jsonrpc": "2.0", "id": 1, "method": "getVoteAccounts", "params": [ ] })
votekeys = [ { "votePubkey": i['votePubkey'] } for i in res['result']['current'] ]

res = good_method({"jsonrpc": "2.0", "id": 1, "method": "getVoteAccounts", "params": votekeys[:3] })
assert len(res['result']['current']) > 0

good_method({"id":3,"jsonrpc":"2.0","method":"sendTransaction","params":["ASo+eUIKwuSWNkIUSGYqsCyMl8laigvXBY0voPWtK+spyJ6aoKx6aD92w8debhg4OOtIcLmWcpiczHY0IuMFDwcBAAEDdyLB10ajX5sIZk3tYD6EBxTn7SNadMPcbamf1i/4s5Q5gs3samJ1XGBBSM+gZo2HLoRzniskcYjPZjKIdB2iqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1nrHFeO6WRyL7j0okdIcbRu3jwqxJ7McfyD/5KbTM8wBAgIAAQwCAAAAAACKXXhFYwE=",{"encoding":"base64","maxRetries":None,"minContextSlot":None,"preflightCommitment":"confirmed","skipPreflight":False}]})
bad_method({"id":3,"jsonrpc":"2.0","method":"sendTransaction","params":["ASo+eUIKwuSWNkIUSGYqsCyMl8laigvXBY0voPWtK+spyJ6aoKx6aD92w8debhg4OOtIcLmWcpiczHY0IuMFDwcBAAEDdyLB10ajX5sIZk3tYD6EBxTn7SNadMPcbamf1i/4s5Q5gs3samJ1XGBBSM+gZo2HLoRzniskcYjPZjKIdB2iqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1nrHFeO6WRyL7j0okdIcbRu3jwqxJ7McfyD/5KbTM8wBAgIAAQwCAAAAAACKXXhFYwE=",{"encoding":"base64x","maxRetries":None,"minContextSlot":None,"preflightCommitment":"confirmed","skipPreflight":False}]})
bad_method({"id":3,"jsonrpc":"2.0","method":"sendTransaction","params":[{"encoding":"base64","maxRetries":None,"minContextSlot":None,"preflightCommitment":"confirmed","skipPreflight":False}]})
bad_method({"id":3,"jsonrpc":"2.0","method":"sendTransaction","params":["\x0001ASo+eUIKwuSWNkIUSGYqsCyMl8laigvXBY0voPWtK+spyJ6aoKx6aD92w8debhg4OOtIcLmWcpiczHY0IuMFDwcBAAEDdyLB10ajX5sIZk3tYD6EBxTn7SNadMPcbamf1i/4s5Q5gs3samJ1XGBBSM+gZo2HLoRzniskcYjPZjKIdB2iqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1nrHFeO6WRyL7j0okdIcbRu3jwqxJ7McfyD/5KbTM8wBAgIAAQwCAAAAAACKXXhFYwE=",{"encoding":"base64","maxRetries":None,"minContextSlot":None,"preflightCommitment":"confirmed","skipPreflight":False}]})
bad_method({"id":3,"jsonrpc":"2.0","method":"sendTransaction","params":["eUIKwuSWNkIUSGYqsCyMl8laigvXBY0voPWtK+spyJ6aoKx6aD92w8debhg4OOtIcLmWcpiczHY0IuMFDwcBAAEDdyLB10ajX5sIZk3tYD6EBxTn7SNadMPcbamf1i/4s5Q5gs3samJ1XGBBSM+gZo2HLoRzniskcYjPZjKIdB2iqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1nrHFeO6WRyL7j0okdIcbRu3jwqxJ7McfyD/5KbTM8wBAgIAAQwCAAAAAACKXXhFYwE=",{"encoding":"base64","maxRetries":None,"minContextSlot":None,"preflightCommitment":"confirmed","skipPreflight":False}]})

good_method({"jsonrpc":"2.0", "id": 1, "method": "getSlotLeader"})

good_method({"jsonrpc":"2.0", "id": 1, "method": "getSlotLeaders", "params": [slot, 10]})

async def hello():
    async with websockets.connect(url.replace('http:','ws:')) as websocket:
        for a in accts:
            arg = { "jsonrpc": "2.0", "id": 1, "method": "accountSubscribe", "params": [ a, { "encoding": "base64", "commitment": "finalized" } ] }
            print(arg)
            await websocket.send(json.dumps(arg))
            await asyncio.sleep(1)
        arg = { "jsonrpc": "2.0", "id": 1, "method": "slotSubscribe" }
        print(arg)
        await websocket.send(json.dumps(arg))
        await asyncio.sleep(1)

        cnt = 0
        while cnt < 50:
            print(json.loads(await websocket.recv()))
            cnt = cnt+1

        await websocket.close()

asyncio.get_event_loop().run_until_complete(hello())

def fuzz_test(f):
    def try_bytes(data):
        return requests.post(url,headers={'Content-Type':'application/json'},data=data).content

    print()
    print(f)
    print(try_bytes(f))

    for i in range(len(f)):
        try_bytes(f[:i] + b'\x00' + f[i:])
        try_bytes(f[:i] + b'\x01' + f[i:])
        try_bytes(f[:i] + b'x' + f[i:])
        try_bytes(f[:i] + b'000' + f[i:])
        try_bytes(f[:i] + b' ' + f[i:])
        if i > 0:
            try_bytes(f[:i-1] +  f[i:])

    i = 0
    while True:
        while i < len(f) and f[i] != 34:
            i = i+1
            continue
        if i == len(f):
            break
        j = i+1
        while j < len(f) and f[j] != 34:
            j = j+1
            continue
        if j == len(f):
            break

        try_bytes(f[:i+1] + f[j:])
        try_bytes(f[:i+1] + b'xxx' + f[j:])
        try_bytes(f[:i+1] + b'0123' + f[j:])
        try_bytes(f[:i+1] + b'cat' + f[j:])

        i = j+1

if fuzz:
    for f in fixtures:
        fuzz_test(f)

print('Test passed!')
