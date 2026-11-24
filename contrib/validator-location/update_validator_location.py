#!/usr/bin/env python3

"""
Registers your validator's location in its vote account (SIMD-0674).

The location is an ECEF (x, y, z) point in meters: the spot directly
below your validator, at height 0. Height here means height above the
WGS84 ellipsoid, which is roughly sea level. See
https://github.com/solana-foundation/solana-improvement-documents/pull/674 and
https://github.com/solana-foundation/solana-improvement-documents/pull/675 for
more information.

You can get the point from your latitude and longitude at
https://gnsscalc.com/coordinates with Geodetic height set to 0. Round
to whole meters.

The transaction has to be signed by the vote account's authorized
voter, which is usually your validator identity keypair. That keypair
also pays the fee unless you pass --fee-payer.

Example, for a validator in Frankfurt:

    ECEF_X=4051542 ECEF_Y=618526 ECEF_Z=4870645
    python3 update_validator_location.py -u http://<rpc> \\
        SomeVoteAccount1111111111111111111111111111 $ECEF_X $ECEF_Y $ECEF_Z \\
        /path/to/validator-keypair.json \\
        --fee-payer /path/to/fee-payer.json

By default the transaction is sent with the RPC's sendTransaction. If
your RPC doesn't support that (Firedancer's RPC doesn't), you can send
it straight to the TPU instead.

To send it to the next few leaders' UDP TPU ports:

    ECEF_X=4051542 ECEF_Y=618526 ECEF_Z=4870645
    python3 update_validator_location.py -u http://<rpc> \\
        SomeVoteAccount1111111111111111111111111111 $ECEF_X $ECEF_Y $ECEF_Z \\
        /path/to/validator-keypair.json \\
        --fee-payer /path/to/fee-payer.json \\
        --tpu-leaders

To send it to one node, e.g. your own validator on port 9001. It only
lands when that node is leader, so this is mostly useful for testing:

    ECEF_X=4051542 ECEF_Y=618526 ECEF_Z=4870645
    python3 update_validator_location.py -u http://<rpc> \\
        SomeVoteAccount1111111111111111111111111111 $ECEF_X $ECEF_Y $ECEF_Z \\
        /path/to/validator-keypair.json \\
        --fee-payer /path/to/fee-payer.json \\
        --tpu 203.0.113.10:9001

Note that registering your location also upgrades your vote account
state to a vote state v5.
"""

import argparse
import base64
import hashlib
import json
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

VOTE_PROGRAM_ID = "Vote111111111111111111111111111111111111111"
UPDATE_LOCATION_DISCRIMINANT = 20
VOTE_STATE_V5 = 4
VOTE_STATE_V5_LOCATION_OFFSET = 132
LEADER_FANOUT_SLOTS = 12

COORD_MAX = 6378138
SURFACE_DIST2 = 40680631590769
FLATTENING_CORRECTION = 442
SURFACE_TOLERANCE = 12756274000

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

P = (2**255) - 19
L = (2**252) + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


class UpdateLocationError(Exception):
    pass


def b58encode(raw):
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r] + out
    pad = len(raw) - len(raw.lstrip(b"\0"))
    return ("1" * pad) + out


def b58decode(s):
    n = 0
    for c in s:
        if c not in B58_ALPHABET:
            raise UpdateLocationError(f"invalid base58 string: {s}")
        n = (n * 58) + B58_ALPHABET.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return (b"\0" * pad) + raw


def decode_pubkey(s):
    raw = b58decode(s)
    if len(raw) != 32:
        raise UpdateLocationError(f"invalid pubkey: {s}")
    return raw


def _point_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    pa = ((y1 - x1) * (y2 - x2)) % P
    pb = ((y1 + x1) * (y2 + x2)) % P
    pc = (2 * t1 * t2 * D) % P
    pd = (2 * z1 * z2) % P
    e, f, g, h = pb - pa, pd - pc, pd + pc, pb + pa
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _point_mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_compress(p):
    x, y, z, _ = p
    zinv = pow(z, P - 2, P)
    x = (x * zinv) % P
    y = (y * zinv) % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _recover_x(y, sign):
    x2 = ((y * y) - 1) * pow((D * y * y) + 1, P - 2, P)
    x = pow(x2, (P + 3) // 8, P)
    if ((x * x) - x2) % P != 0:
        x = (x * SQRT_M1) % P
    if (x & 1) != sign:
        x = P - x
    return x


_G_Y = (4 * pow(5, P - 2, P)) % P
_G_X = _recover_x(_G_Y, 0)
_G = (_G_X, _G_Y, 1, (_G_X * _G_Y) % P)


def _expand_seed(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _sha512_mod_l(data):
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % L


def ed25519_public_key(seed):
    a, _ = _expand_seed(seed)
    return _point_compress(_point_mul(a, _G))


def ed25519_sign(seed, msg):
    a, prefix = _expand_seed(seed)
    public = _point_compress(_point_mul(a, _G))
    r = _sha512_mod_l(prefix + msg)
    big_r = _point_compress(_point_mul(r, _G))
    h = _sha512_mod_l(big_r + public + msg)
    s = (r + (h * a)) % L
    return big_r + s.to_bytes(32, "little")


def is_valid_location(x, y, z):
    if any(c < -COORD_MAX or c > COORD_MAX for c in (x, y, z)):
        return False
    z2 = z * z
    dist2 = (x * x) + (y * y) + z2 + ((FLATTENING_CORRECTION * z2) >> 16)
    return (SURFACE_DIST2 - SURFACE_TOLERANCE) <= dist2 <= (SURFACE_DIST2 + SURFACE_TOLERANCE)


def update_location_data(x, y, z):
    return struct.pack("<Iiii", UPDATE_LOCATION_DISCRIMINANT, x, y, z)


def _shortvec(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def update_location_message(payer, vote, voter, data, blockhash):
    program = decode_pubkey(VOTE_PROGRAM_ID)
    metas = {}
    for key, signer, writable in [
        (payer, True, True),
        (vote, False, True),
        (voter, True, False),
        (program, False, False),
    ]:
        s, w = metas.get(key, (False, False))
        metas[key] = (s or signer, w or writable)

    def category(signer, writable):
        return [k for k in sorted(metas) if k != payer and metas[k] == (signer, writable)]

    writable_signers = [payer] + category(True, True)
    readonly_signers = category(True, False)
    writable_unsigned = category(False, True)
    readonly_unsigned = category(False, False)
    keys = writable_signers + readonly_signers + writable_unsigned + readonly_unsigned

    header = bytes(
        [len(writable_signers) + len(readonly_signers), len(readonly_signers), len(readonly_unsigned)]
    )
    ix = (
        bytes([keys.index(program)])
        + _shortvec(2)
        + bytes([keys.index(vote), keys.index(voter)])
        + _shortvec(len(data))
        + data
    )
    return header + _shortvec(len(keys)) + b"".join(keys) + blockhash + _shortvec(1) + ix


def signed_transaction(msg, seeds):
    num_signers = msg[0]
    signer_keys = [msg[4 + (32 * i) : 4 + (32 * (i + 1))] for i in range(num_signers)]
    by_pubkey = {ed25519_public_key(seed): seed for seed in seeds}
    sigs = []
    for key in signer_keys:
        if key not in by_pubkey:
            raise UpdateLocationError(f"missing signer {b58encode(key)}")
        sigs.append(ed25519_sign(by_pubkey[key], msg))
    return _shortvec(num_signers) + b"".join(sigs) + msg


def load_keypair(path):
    try:
        with open(path) as f:
            values = json.load(f)
    except (OSError, ValueError) as e:
        raise UpdateLocationError(f"cannot read keypair {path}: {e}")
    if not isinstance(values, list) or len(values) != 64 or not all(
        isinstance(v, int) and 0 <= v <= 255 for v in values
    ):
        raise UpdateLocationError(f"{path} is not a 64-byte Solana keypair file")
    raw = bytes(values)
    seed, pubkey = raw[:32], raw[32:]
    if ed25519_public_key(seed) != pubkey:
        raise UpdateLocationError(f"{path}: public key does not match secret key")
    return seed, pubkey


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            reply = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise UpdateLocationError(f"{method}: HTTP {e.code} from {url}")
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise UpdateLocationError(f"{method}: {e}")
    if "error" in reply:
        err = reply["error"]
        logs = (err.get("data") or {}).get("logs") if isinstance(err.get("data"), dict) else None
        detail = f"{method}: {err.get('message', err)}"
        if logs:
            detail += "\n" + "\n".join(f"  {line}" for line in logs)
        raise UpdateLocationError(detail)
    return reply["result"]


def check_vote_account(url, vote):
    info = rpc(url, "getAccountInfo", [b58encode(vote), {"encoding": "base64", "commitment": "confirmed"}])
    if info["value"] is None:
        raise UpdateLocationError(f"vote account {b58encode(vote)} does not exist")
    owner = info["value"]["owner"]
    if owner != VOTE_PROGRAM_ID:
        raise UpdateLocationError(f"{b58encode(vote)} is owned by {owner}, not the vote program")


def vote_account_location(data):
    if len(data) < (VOTE_STATE_V5_LOCATION_OFFSET + 12) or int.from_bytes(data[:4], "little") != VOTE_STATE_V5:
        return None
    return struct.unpack_from("<iii", data, VOTE_STATE_V5_LOCATION_OFFSET)


def fetch_location(url, vote):
    info = rpc(url, "getAccountInfo", [b58encode(vote), {"encoding": "base64", "commitment": "confirmed"}])
    if info["value"] is None:
        return None
    return vote_account_location(base64.b64decode(info["value"]["data"][0]))


def tpu_address(s):
    host, sep, port = s.rpartition(":")
    host = host.strip("[]")
    if not sep or not host or not port.isdigit() or not (0 < int(port) < 65536):
        raise argparse.ArgumentTypeError(f"expected HOST:PORT, got {s!r}")
    return host, int(port)


def cluster_tpus(url):
    tpus = {}
    for node in rpc(url, "getClusterNodes", []):
        if node.get("tpu"):
            tpus[node["pubkey"]] = tpu_address(node["tpu"])
    if not tpus:
        raise UpdateLocationError("no cluster node advertises a UDP TPU address")
    return tpus


def leader_tpus(url, tpus):
    slot = rpc(url, "getSlot", [{"commitment": "processed"}])
    leaders = rpc(url, "getSlotLeaders", [slot, LEADER_FANOUT_SLOTS])
    return list(dict.fromkeys(tpus[leader] for leader in leaders if leader in tpus))


def send_via_tpu(url, tx, vote, location, last_valid_block_height, targets):
    sig = b58encode(tx[1:65])
    print(f"Signature: {sig}")
    seen = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        while True:
            for addr in targets():
                if addr not in seen:
                    print(f"Sending to TPU {addr[0]}:{addr[1]}")
                    seen.add(addr)
                try:
                    sock.sendto(tx, addr)
                except OSError as e:
                    raise UpdateLocationError(f"cannot send to {addr[0]}:{addr[1]}: {e}")
            if fetch_location(url, vote) == location:
                return sig
            if rpc(url, "getBlockHeight", [{"commitment": "confirmed"}]) > last_valid_block_height:
                raise UpdateLocationError(
                    f"location was not registered before the blockhash expired; transaction {sig} "
                    "may have failed on-chain"
                )
            time.sleep(1)


def send_and_confirm(url, tx, last_valid_block_height):
    sig = b58encode(tx[1:65])
    rpc(
        url,
        "sendTransaction",
        [
            base64.b64encode(tx).decode(),
            {"encoding": "base64", "skipPreflight": True},
        ],
    )
    print(f"Signature: {sig}")
    while True:
        status = rpc(url, "getSignatureStatuses", [[sig]])["value"][0]
        if status is not None:
            if status.get("err") is not None:
                raise UpdateLocationError(f"transaction {sig} failed: {status['err']}")
            if status.get("confirmationStatus") in ("confirmed", "finalized"):
                return sig
        if rpc(url, "getBlockHeight", [{"commitment": "confirmed"}]) > last_valid_block_height:
            raise UpdateLocationError(f"transaction {sig} was not confirmed before its blockhash expired")
        time.sleep(1)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Register a validator's location (SIMD-0674 UpdateLocation) in its vote account."
    )
    parser.add_argument("-u", "--url", required=True, help="RPC URL of the cluster")
    parser.add_argument("vote_account", metavar="VOTE_ACCOUNT_ADDRESS", help="Vote account to update")
    parser.add_argument("x", metavar="X", type=int, help="WGS84 ECEF X coordinate, in whole meters, of the point at height 0 directly below the validator")
    parser.add_argument("y", metavar="Y", type=int, help="WGS84 ECEF Y coordinate, in whole meters, of the point at height 0 directly below the validator")
    parser.add_argument("z", metavar="Z", type=int, help="WGS84 ECEF Z coordinate, in whole meters, of the point at height 0 directly below the validator")
    parser.add_argument("authorized_voter", metavar="AUTHORIZED_KEYPAIR", help="Authorized voter keypair file")
    parser.add_argument("--fee-payer", metavar="KEYPAIR", help="Fee payer keypair file (default: the authorized voter)")
    tpu = parser.add_mutually_exclusive_group()
    tpu.add_argument(
        "--tpu",
        metavar="HOST:PORT",
        type=tpu_address,
        help="Send the transaction to this UDP TPU address instead of the RPC's sendTransaction",
    )
    tpu.add_argument(
        "--tpu-leaders",
        action="store_true",
        help="Send the transaction to the upcoming leaders' UDP TPU addresses instead of the RPC's sendTransaction",
    )
    args = parser.parse_args(argv)
    if not is_valid_location(args.x, args.y, args.z):
        parser.error(
            f"location ({args.x}, {args.y}, {args.z}) is not within 1 km of the WGS84 ellipsoid; "
            "use the ECEF point at height 0 directly below the validator"
        )
    return args


def run(args):
    vote = decode_pubkey(args.vote_account)
    voter_seed, voter = load_keypair(args.authorized_voter)
    if args.fee_payer:
        payer_seed, payer = load_keypair(args.fee_payer)
    else:
        payer_seed, payer = voter_seed, voter

    check_vote_account(args.url, vote)
    latest = rpc(args.url, "getLatestBlockhash", [{"commitment": "confirmed"}])["value"]
    blockhash = decode_pubkey(latest["blockhash"])

    data = update_location_data(args.x, args.y, args.z)
    msg = update_location_message(payer, vote, voter, data, blockhash)
    tx = signed_transaction(msg, [payer_seed, voter_seed])

    print(f"Vote account:     {b58encode(vote)}")
    print(f"Authorized voter: {b58encode(voter)}")
    print(f"Fee payer:        {b58encode(payer)}")
    print(f"Location:         ({args.x}, {args.y}, {args.z})")
    if args.tpu or args.tpu_leaders:
        if args.tpu:
            targets = lambda: [args.tpu]
        else:
            tpus = cluster_tpus(args.url)
            targets = lambda: leader_tpus(args.url, tpus)
        location = (args.x, args.y, args.z)
        send_via_tpu(args.url, tx, vote, location, latest["lastValidBlockHeight"], targets)
        print(f"Location registered: ({args.x}, {args.y}, {args.z})")
    else:
        sig = send_and_confirm(args.url, tx, latest["lastValidBlockHeight"])
        print(f"Confirmed: {sig}")


def main(argv=None):
    args = parse_args(argv)
    try:
        run(args)
    except UpdateLocationError as e:
        sys.stdout.flush()
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
