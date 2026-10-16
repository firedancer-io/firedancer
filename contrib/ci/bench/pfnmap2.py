# pfnmap2.py PID: physical frame + kpageflags of every resident page of every mapping (needs root).
# hugetlb/THP-sized mappings: one entry per kernel page.  line: name range perms offset kps_kB entries...
# entry: pfn:flagshex (kpageflags), "~N" = N absent pages
import sys, struct
pid = sys.argv[1]
kps, cur = {}, None
for line in open(f"/proc/{pid}/smaps"):
    f = line.split()
    if f and not f[0].endswith(":"): cur = f[0]
    elif f and f[0] == "KernelPageSize:": kps[cur] = int(f[1])
try: kf = open("/proc/kpageflags", "rb")
except OSError: kf = None
with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/pagemap", "rb") as pm:
    for line in maps:
        f = line.split()
        name = f[5] if len(f) > 5 else "[anon]"
        if name in ("[vvar]", "[vdso]", "[vsyscall]"): continue
        lo, hi = (int(x, 16) for x in f[0].split("-"))
        k = kps.get(f[0], 4); step = max(k // 4, 1)
        n = (hi - lo) // 4096
        if step == 1:
            pm.seek(lo // 4096 * 8); ents = struct.unpack(f"<{n}Q", pm.read(n * 8))
        else:
            ents = []
            for va in range(lo, hi, step * 4096):
                pm.seek(va // 4096 * 8); ents.append(struct.unpack("<Q", pm.read(8))[0])
        out, gap = [], 0
        for e in ents:
            if not e >> 63: gap += 1; continue
            if gap: out.append(f"~{gap}"); gap = 0
            pfn = e & ((1 << 55) - 1); fl = 0
            if kf and pfn:
                kf.seek(pfn * 8); fl = struct.unpack("<Q", kf.read(8))[0]
            out.append(f"{pfn}:{fl:x}")
        if gap: out.append(f"~{gap}")
        print(name, f[0], f[1], f[2], k, " ".join(out))
