#!/usr/bin/env python3

import asyncio
import websockets
import json
import logging
import sys
import subprocess

logging.basicConfig(
    format="%(asctime)s %(message)s",
    level=logging.INFO,
)

async def hello():
    #uri = "wss://api.testnet.solana.com"
    # uri = "ws://localhost:8900"
    async with websockets.connect(sys.argv[1]) as websocket:
#        arg = { "jsonrpc": "2.0", "id": 1, "method": "accountSubscribe", "params": [ "HiFjzpR7e5Kv2tdU9jtE4FbH1X8Z9Syia3Uadadx18b5", { "encoding": "base64", "commitment": "finalized" } ] }
        arg = { "jsonrpc": "2.0", "id": 1, "method": "slotSubscribe" }
        await websocket.send(json.dumps(arg))
        while True:
            print(await websocket.recv())
            
            

asyncio.get_event_loop().run_until_complete(hello())
