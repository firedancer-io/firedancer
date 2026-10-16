# pfnmap.py PID: physical frame of every resident 4 KiB page of the process's non-hugetlb mappings (needs root)
import sys, struct
pid = sys.argv[1]
with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/pagemap", "rb") as pm:
    for line in maps:
        f = line.split()
        name = f[5] if len(f) > 5 else "[anon]"
        if name.startswith("/mnt/.fd") or name in ("[vvar]", "[vdso]", "[vsyscall]"): continue
        lo, hi = (int(x, 16) for x in f[0].split("-"))
        if hi - lo > 1 << 31: continue
        pm.seek(lo // 4096 * 8); d = pm.read((hi - lo) // 4096 * 8)
        pfns = [e & ((1 << 55) - 1) if e >> 63 else -1 for e in struct.unpack(f"<{len(d)//8}Q", d)]
        print(name, f[0], f[1], f[2], " ".join(map(str, pfns)))
