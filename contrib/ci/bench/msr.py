#!/usr/bin/env python3
# msr.py snap OUT : APERF/MPERF of every online cpu -> OUT (json)
import json, os, struct, sys, time
def rd(c, reg):
    with open(f"/dev/cpu/{c}/msr", "rb") as f:
        f.seek(reg); return struct.unpack("<Q", f.read(8))[0]
cpus = sorted(int(d[3:]) for d in os.listdir("/sys/devices/system/cpu") if d[3:].isdigit())
json.dump({"t": time.time(), "a": [rd(c, 0xE8) for c in cpus], "m": [rd(c, 0xE7) for c in cpus]}, open(sys.argv[2], "w"))
