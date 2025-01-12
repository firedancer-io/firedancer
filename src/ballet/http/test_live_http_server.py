import asyncio
import websockets
import requests
import json

for i in range(5000):
    x = requests.get("http://localhost:4321/hello/from/the/magic/tavern")
    print(x.content.decode('utf-8'))

for i in range(20):
    arg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            "vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg",
            {
                "encoding": "base58"
            }
        ]
    }
    x = requests.post("http://localhost:4321/",json=arg)
    res = json.loads(x.content)
    print(res)

async def hello():
    uri = "ws://localhost:4321"
    async with websockets.connect(uri) as websocket:
        arg = { "jsonrpc": "2.0", "id": 1, "method": "slotSubscribe" }
        await websocket.send(json.dumps(arg))
        while True:
            print(json.dumps(json.loads(await websocket.recv()),indent=2))

asyncio.get_event_loop().run_until_complete(hello())

print('Test passed!')
