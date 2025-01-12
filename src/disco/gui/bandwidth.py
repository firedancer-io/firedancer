import asyncio
import websockets
import time
import json
from collections import defaultdict

async def measure_bandwidth(uri):
    async with websockets.connect(uri, max_size=1_000_000_000) as websocket:
        start_time = time.time()
        total_bytes_by_group = defaultdict(int)
        overall_total_bytes = 0

        while True:
            frame = await websocket.recv()
            data = json.loads(frame)
            topic = data.get("topic")
            key = data.get("key")
            group = (topic, key)
            total_bytes_by_group[group] += len(frame)
            overall_total_bytes += len(frame)
            elapsed_time = time.time() - start_time

            if elapsed_time >= 1.0:
                bandwidths = []
                for group, total_bytes in total_bytes_by_group.items():
                    bandwidth_mbps = (total_bytes * 8) / (elapsed_time * 1_000_000)
                    if bandwidth_mbps >= 0.001:
                        bandwidths.append((group, bandwidth_mbps))
                
                # Sort by bandwidth in descending order
                bandwidths.sort(key=lambda x: x[1], reverse=True)
                
                for group, bandwidth_mbps in bandwidths:
                    print(f"Incoming bandwidth for {group}: {bandwidth_mbps:.2f} Mbps")
                
                # Calculate and print the overall total bandwidth
                overall_bandwidth_mbps = (overall_total_bytes * 8) / (elapsed_time * 1_000_000)
                print(f"Total incoming bandwidth: {overall_bandwidth_mbps:.2f} Mbps")
                
                start_time = time.time()
                total_bytes_by_group.clear()
                overall_total_bytes = 0

asyncio.get_event_loop().run_until_complete(measure_bandwidth('ws://localhost:80/websocket'))
