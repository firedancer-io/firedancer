#!/usr/bin/env python3
"""Benchmark PR comment: bench.sh raw outputs -> rows JSON -> comment body.

  benchmark_comment.py rows   --job JOB --bench-dir DIR --head SHA --base SHA --run-id ID --status S > rows.json
  benchmark_comment.py render --state old.json --rows rows.json --out-body body.md --out-state new.json --out-summary summary.md
"""
import json, os, re, sys

JOBS = ("replay", "snapshot", "bench")
TIERS = " +!-"  # noise, improved, warning, regression: diff-fence gutter chars, in severity order

def read(d, s, name):
    return open(f"{d}/{s}.{name}").read()

def summary(d, s, what):  # "TAG k=v k=v ..." -> {k: v}
    tag = "BENCH_SUMMARY" if what == "bench" else "BACKTEST_SUMMARY"
    m = re.search(tag + r" (.*)", read(d, s, what + ".log"))
    if not m: raise LookupError(f"{s}.{what}.log: no {tag}")
    return {k: float(v) for k, v in (t.split("=") for t in m[1].split())}

def stamp(log, needle):  # seconds since midnight of the first log line containing needle
    line = next((l for l in log.splitlines() if needle in l), None)
    if not line: raise LookupError(needle)
    h, m, s = re.match(r"\S+\s+\S+ (\d\d):(\d\d):(\S+) ", line).groups()
    return int(h) * 3600 + int(m) * 60 + float(s)

def snapshot_load(d, s):
    log = read(d, s, "snapshot.log")
    return (stamp(log, "replay ready at slot") - stamp(log, "reading full snapshot from file")) % 86400  # midnight

def mem(d, s, cluster):
    return json.loads(read(d, s, f"build.mem.{cluster}.json"))["summary"]["total_memory_locked_bytes"] / 2**30

# id, label, job, value(bench_dir, side), format, warn %, regression %, higher is better
ROWS = (
    ("replay_tps",    "replay tps, mainnet",       "replay",   lambda d, s: summary(d, s, "replay")["tps"],                ",.0f tps",   0.5, 2.0, True),
    ("bench_tps",     "bench tps, localnet",       "bench",    lambda d, s: summary(d, s, "bench")["tps"],                 ",.0f tps",   0.5, 2.0, True),
    ("snapshot_load", "snapshot load, testnet",    "snapshot", snapshot_load,                                              ".2f s",      3.0, 8.0, False),
    ("mem_mainnet",   "mem total, mainnet",        "replay",   lambda d, s: mem(d, s, "mainnet"),                          ".2f GiB",    0.0, 1.0, False),
    ("mem_testnet",   "mem total, testnet",        "replay",   lambda d, s: mem(d, s, "testnet"),                          ".2f GiB",    0.0, 1.0, False),
    ("compile",       "clean compile, firedancer", "replay",   lambda d, s: sum(map(float, read(d, s, "build.time").split()[1:])), ".1f cpu·s",  2.0, 5.0, False),  # user+sys
    ("binsize",       "binary size, firedancer",   "replay",   lambda d, s: os.path.getsize(f"{d}/{s}/bin/firedancer") / 1e6, ".2f MB",     0.5, 2.0, False),
)
HIST_HDR = ("TPS", "BENCH", "SNAP", "MEM·M", "MEM·T", "COMPILE", "BINARY")

def tier(row, d):
    _, _, _, _, _, warn, red, up = row
    worse = -d if up else d
    if abs(worse) <= warn: return " "
    return "+" if worse < 0 else "-" if worse >= red else "!"

def pct(d, w):
    return ("0.00%" if round(d, 2) == 0 else f"{d:+.2f}%").rjust(w)

def rule(prefix, w):
    return prefix + "─" * (w - len(prefix))

def known_rows(state):
    return {k: v for run in state["runs"].values() for k, v in run["rows"].items()}

def deltas(state):  # {row id: (base, new, Δ%)} for every row with both sides measured
    return {k: (v["base"], v["new"], (v["new"] - v["base"]) / v["base"] * 100)
            for k, v in known_rows(state).items() if v["base"] is not None and v["new"] is not None}

def worst(state, ds):
    if crashed(state, ds): return "-"
    return max((tier(r, ds[r[0]][2]) for r in ROWS if r[0] in ds), key=TIERS.index, default=" ")

def crashed(state, ds):  # rows a failed job never measured: a regression, not noise
    return [r for r in ROWS if state["runs"].get(r[2], {}).get("status") == "failed" and r[0] not in ds]

def measure(value, d, side):
    try: return value(d, side)
    except (FileNotFoundError, LookupError): return None  # not measured, or a binary without the summary lines

def rows(a):
    out = {}
    for rid, _, job, value, *_ in ROWS:
        if job == a["job"]:
            m = {side: measure(value, a["bench-dir"], side) for side in ("base", "new")}
            if any(v is not None for v in m.values()): out[rid] = m
    json.dump({"job": a["job"], "head": a["head"], "base": a["base"], "run_id": int(a["run-id"]), "status": a["status"], "rows": out}, sys.stdout)

def render(a):
    new = json.load(open(a["rows"]))
    state = json.load(open(a["state"])) if os.path.getsize(a["state"]) else {"head": "", "base": "", "runs": {}, "history": []}
    state["seq"] = state.get("seq", 0) + 1  # upsert.js only writes if the comment still carries the seq it read
    if state["head"] and new["head"] != state["head"]:  # new push: the old one becomes history
        ds = deltas(state)
        state["history"] = [{"head": state["head"], "rows": {k: v[2] for k, v in ds.items()}, "tier": worst(state, ds)}] + state["history"][:9]
        state["runs"] = {}
    state.update(head=new["head"], base=new["base"])
    state["runs"][new["job"]] = {k: new[k] for k in ("run_id", "status", "rows")}

    ds, known = deltas(state), known_rows(state)
    done = {j for j, run in state["runs"].items() if run["status"] == "done"}
    failed = {j for j, run in state["runs"].items() if run["status"] == "failed"}
    dead = crashed(state, ds)
    cell = lambda fmt, v: (format(v, fmt.split(" ")[0]) + " " + fmt.split(" ", 1)[1] if v is not None else "…").rjust(11)
    lines = [rule(f" ┌─ ⚡ PERF · {state['head'][:7]} vs main@{state['base'][:7]} ", 70),  # ⚡ is two cells wide
             " │ " + "SUITE".ljust(33) + "BASELINE".rjust(11) + "  " + "NEW".rjust(11) + "  " + "Δ".rjust(8)]
    for row in ROWS:
        rid, label, _, _, fmt, *_ = row
        m = known.get(rid, {"base": None, "new": None})
        new = cell(fmt, m["new"])
        if rid in ds:
            d = ds[rid][2]
            t = tier(row, d)
            arrow = "·" if t == " " else "▲" if d > 0 else "▼"
            delta = arrow + pct(d, 8)
        elif row in dead:
            t, delta, new = "-", "…".rjust(8), "failed".rjust(11)
        else:
            t, delta = " ", "…".rjust(8)
        lines.append(t + "│ " + label.ljust(33) + cell(fmt, m["base"]) + "  " + new + "  " + delta)
    lines.append(rule(" ├", 71))
    if done | failed == set(JOBS):
        n = {t: sum(tier(r, ds[r[0]][2]) == t for r in ROWS if r[0] in ds) for t in TIERS}
        n["-"] += len(dead)
        s = lambda t: "" if n[t] == 1 else "S"
        missing = len(ROWS) - len(ds) - len(dead)
        lines.append(f"@@ {n['-']} REGRESSION{s('-')} · {n['!']} WARNING{s('!')} · {n['+']} IMPROVED · {n[' ']} NOISE"
                     + (f" · {missing} UNMEASURED" if missing else "") + " @@")
    else:
        lines.append("@@ RUNNING · " + " · ".join(f"{j} {'done' if j in done else 'failed' if j in failed else 'pending'}" for j in JOBS) + " @@")
    lines.append(rule(" └", 71))
    body = "```diff\n" + "\n".join(lines) + "\n```\n"
    if done | failed != set(JOBS) and a.get("spinner"):  # HTML can't render inside the fence, so the spinner sits above it
        body = f'<img src="{a["spinner"]}" width="14" height="14" alt="running">\n\n' + body

    if state["history"]:
        pushes = [{"head": state["head"], "rows": {k: v[2] for k, v in ds.items()}, "tier": worst(state, ds)}] + state["history"]
        lines = [rule(" ┌─ HISTORY · Δ vs main, per push, newest first ", 73),
                 " │ " + "HEAD".ljust(7) + "".join(h.rjust(9) for h in HIST_HDR)]
        for p in pushes:
            lines.append(p["tier"] + "│ " + p["head"][:7].ljust(7) + "".join(pct(p["rows"][r[0]], 9) if r[0] in p["rows"] else "…".rjust(9) for r in ROWS))
        lines.append(rule(" └", 73))
        body += f"\n<details><summary>history · {len(pushes)} pushes</summary>\n\n```diff\n" + "\n".join(lines) + "\n```\n\n</details>\n"

    st = json.dumps(state, separators=(",", ":"))
    open(a["out-body"], "w").write(f"<!-- fd-benchmark-comment:v1 -->\n{body}<!-- fd-benchmark-state {st} -->\n")
    open(a["out-state"], "w").write(st)
    open(a["out-summary"], "w").write(body)

if __name__ == "__main__":
    cmd, *argv = sys.argv[1:]
    {"rows": rows, "render": render}[cmd](dict(zip((k.lstrip("-") for k in argv[::2]), argv[1::2])))
