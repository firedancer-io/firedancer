import asyncio
import websockets
import json

async def dump_messages(uri):
    async with websockets.connect(uri, max_size=1_000_000_000) as websocket:
        while True:
            frame = await websocket.recv()
            print(json.dumps(json.loads(frame)))

asyncio.get_event_loop().run_until_complete(dump_messages('ws://localhost:80/websocket'))
