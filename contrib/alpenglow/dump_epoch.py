#!/usr/bin/env python3
"""Dump the Alpenglow epoch validator set for `firedancer-dev votor`.

Writes the binary consumed by the agepoch tile in
src/app/firedancer-dev/commands/votor.c:

    header (81B, packed LE)
        u64 magic = 0x4147455001
        u64 epoch
        u64 start_slot
        u64 slot_cnt
        u64 tip_slot
        u64 voter_cnt
        epoch_schedule: u64 slots_per_epoch, u64 leader_schedule_slot_offset,
                        u8 warmup, u64 first_normal_epoch, u64 first_normal_slot
    voter_cnt * (120B, packed)
        32B vote_key, 32B id_key, u64 stake, 48B compressed BLS pubkey

The set must match agave's `BLSPubkeyToRankMap` exactly, or ranks will
disagree and vote signatures will fail to verify.  That means applying the
same admission rules agave does:

  - `epochVoteAccount` true (the SIMD-0357 VAT-filtered epoch stakes; see
    Bank::get_top_epoch_stakes -> VoteAccounts::clone_and_filter_for_vat)
  - non-zero stake
  - a BLS pubkey present in the VoteStateV4 account
  - duplicate node_pubkey or bls_pubkey drops *both* entries
    (BLSPubkeyToRankMap::new)

Usage:
    ./dump_epoch.py --url http://213.239.141.16:8899 -o epoch.bin
"""

import argparse
import base64
import json
import struct
import sys
import urllib.request

MAGIC = 0x4147455001

# VoteStateV4 field offsets: u32 version, node_pubkey, authorized_withdrawer,
# inflation_rewards_collector, block_revenue_collector, u16 commission,
# u16 block_revenue_commission, u64 pending_delegator_rewards.
BLS_OFF = 4 + 32 + 32 + 32 + 32 + 2 + 2 + 8
BLS_SZ = 48
VOTE_STATE_V4_TAG = 3

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes(32, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    raw = raw[len(raw) - 32:] if len(raw) > 32 else raw
    return b"\0" * pad + raw[-(32 - pad):] if pad else raw.rjust(32, b"\0")


class Rpc:
    def __init__(self, url):
        self.url = url

    def __call__(self, method, params=None):
        body = {"jsonrpc": "2.0", "id": 1, "method": method}
        if params is not None:
            body["params"] = params
        req = urllib.request.Request(
            self.url, json.dumps(body).encode(), {"Content-Type": "application/json"}
        )
        resp = json.load(urllib.request.urlopen(req, timeout=30))
        if "error" in resp:
            sys.exit(f"rpc {method} failed: {resp['error']}")
        return resp["result"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="cluster RPC endpoint")
    ap.add_argument("-o", "--out", default="epoch.bin")
    ap.add_argument(
        "--tip-slot",
        type=int,
        default=None,
        help="slot the synthetic replayed tip starts at (default: current slot)",
    )
    args = ap.parse_args()
    rpc = Rpc(args.url)

    info = rpc("getEpochInfo")
    sched = rpc("getEpochSchedule")
    epoch = info["epoch"]
    start_slot = info["absoluteSlot"] - info["slotIndex"]
    tip_slot = args.tip_slot if args.tip_slot is not None else info["absoluteSlot"]
    print(f"epoch {epoch}: slots {start_slot}..{start_slot + info['slotsInEpoch']}, tip {tip_slot}")

    va = rpc("getVoteAccounts", [{"keepUnstakedDelinquents": True}])
    accounts = [v for g in ("current", "delinquent") for v in va[g]]
    admitted = [v for v in accounts if v["epochVoteAccount"] and v["activatedStake"] > 0]
    print(f"{len(accounts)} vote accounts, {len(admitted)} in epoch stakes with stake")

    keys = [v["votePubkey"] for v in admitted]
    data = {}
    for i in range(0, len(keys), 100):
        chunk = keys[i:i + 100]
        for pk, acct in zip(chunk, rpc("getMultipleAccounts", [chunk, {"encoding": "base64"}])["value"]):
            data[pk] = base64.b64decode(acct["data"][0]) if acct else None

    voters, no_bls = [], 0
    for v in admitted:
        raw = data.get(v["votePubkey"])
        if raw is None or len(raw) < BLS_OFF + 1 + BLS_SZ:
            no_bls += 1
            continue
        if int.from_bytes(raw[0:4], "little") != VOTE_STATE_V4_TAG or raw[BLS_OFF] != 1:
            no_bls += 1
            continue
        voters.append(
            {
                "vote": v["votePubkey"],
                "node": v["nodePubkey"],
                "stake": v["activatedStake"],
                "bls": raw[BLS_OFF + 1: BLS_OFF + 1 + BLS_SZ],
            }
        )
    if no_bls:
        print(f"dropped {no_bls} without a VoteStateV4 BLS pubkey")

    # BLSPubkeyToRankMap::new drops entries whose node or BLS key is not unique.
    node_cnt, bls_cnt = {}, {}
    for v in voters:
        node_cnt[v["node"]] = node_cnt.get(v["node"], 0) + 1
        bls_cnt[v["bls"]] = bls_cnt.get(v["bls"], 0) + 1
    deduped = [v for v in voters if node_cnt[v["node"]] == 1 and bls_cnt[v["bls"]] == 1]
    if len(deduped) != len(voters):
        print(f"dropped {len(voters) - len(deduped)} with duplicate node/BLS pubkeys")
    voters = deduped

    if not voters:
        sys.exit("no admitted voters -- nothing to dump")

    hdr = struct.pack(
        "<QQQQQQQQBQQ",
        MAGIC,
        epoch,
        start_slot,
        info["slotsInEpoch"],
        tip_slot,
        len(voters),
        sched["slotsPerEpoch"],
        sched["leaderScheduleSlotOffset"],
        1 if sched["warmup"] else 0,
        sched["firstNormalEpoch"],
        sched["firstNormalSlot"],
    )
    assert len(hdr) == 81, len(hdr)

    with open(args.out, "wb") as f:
        f.write(hdr)
        for v in sorted(voters, key=lambda x: -x["stake"]):
            rec = b58decode(v["vote"]) + b58decode(v["node"]) + struct.pack("<Q", v["stake"]) + v["bls"]
            assert len(rec) == 120, len(rec)
            f.write(rec)

    total = sum(v["stake"] for v in voters)
    print(f"wrote {args.out}: {len(voters)} voters, {total / 1e9:.0f} SOL total stake")


if __name__ == "__main__":
    main()
