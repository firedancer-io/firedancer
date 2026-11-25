#!/usr/bin/env node
// Walks one Subscribe stream through the watch set operations and checks
// every answer:
//
//   1. subscribe with no filters at the given commitment
//   2. add A, B and X      reply carries the three accounts
//   3. remove A            A stops, B continues
//   4. add C               reply carries C, B and C flow
//   5. add A and a key of 31 bytes   error reply, the set is unchanged
//   6. add A next to a filter        error reply, nothing is changed
//   7. a slots filter      the stream stays open, B and C still flow
//   8. a second Subscribe on the connection is refused, the first goes on
//   9. clear               nothing flows
//  10. add A               reply carries A, only A flows
//
// Every reply has to carry the id of its request, and every reply that
// is not an error the bank id it was read at.
//
// A, B and C should be accounts that are written often, X one that is not.
//
//   node watch.mjs --url http://127.0.0.1:10000 --keys A,B,C,X
//                  [--commitment finalized] [--settle-ms 5000] [--x-token T]
//
// Speaks gRPC over plaintext HTTP/2 with the messages encoded by hand, so
// it needs no generated code and no dependencies.

import http2 from "node:http2";

const arg = (name, dflt) => {
  const i = process.argv.indexOf("--" + name);
  return i >= 0 ? process.argv[i + 1] : dflt;
};
const url = arg("url", "http://127.0.0.1:10000");
const keys = (arg("keys", "") || "").split(",").filter(Boolean);
const commitment = { processed: 0, confirmed: 1, finalized: 2 }[arg("commitment", "finalized")];
const settleMs = Number(arg("settle-ms", "5000"));
const xToken = arg("x-token", "");
if (keys.length !== 4 || commitment === undefined) {
  console.error("usage: watch.mjs --url URL --keys A,B,C,X [--commitment processed|confirmed|finalized] [--settle-ms N]");
  process.exit(2);
}

// base58

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58decode(str) {
  let n = 0n;
  for (const c of str) {
    const d = ALPHABET.indexOf(c);
    if (d < 0) throw new Error("bad base58: " + str);
    n = n * 58n + BigInt(d);
  }
  const out = Buffer.alloc(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; }
  if (n) throw new Error("not a 32 byte key: " + str);
  return out;
}
function b58encode(buf) {
  let n = 0n;
  for (const b of buf) n = (n << 8n) | BigInt(b);
  let s = "";
  while (n) { s = ALPHABET[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b) break; s = "1" + s; }
  return s;
}

// protobuf

function varint(v) {
  v = BigInt(v);
  const out = [];
  while (v > 0x7fn) { out.push(Number(v & 0x7fn) | 0x80); v >>= 7n; }
  out.push(Number(v));
  return Buffer.from(out);
}
const tag = (field, wire) => varint((field << 3) | wire);
const bytesField = (field, body) => Buffer.concat([tag(field, 2), varint(body.length), body]);

function* fields(buf) {
  let o = 0;
  const rd = () => {
    let v = 0n, shift = 0n;
    for (;;) { const b = buf[o++]; v |= BigInt(b & 0x7f) << shift; if (!(b & 0x80)) return v; shift += 7n; }
  };
  while (o < buf.length) {
    const t = Number(rd()), field = t >> 3, wire = t & 7;
    if (wire === 0) yield [field, rd()];
    else if (wire === 2) { const len = Number(rd()); yield [field, buf.subarray(o, o + len)]; o += len; }
    else if (wire === 1) { yield [field, buf.subarray(o, o + 8)]; o += 8; }
    else if (wire === 5) { yield [field, buf.subarray(o, o + 4)]; o += 4; }
    else throw new Error("wire type " + wire);
  }
}

// SubscribeRequest { commitment = 6 }
const subscribeRequest = () => Buffer.concat([tag(6, 0), varint(commitment)]);

// SubscribeRequest { slots = 2 { key = 1 }, commitment = 6 }
const slotsFilter = (name) => bytesField(2, bytesField(1, Buffer.from(name)));
const slotsRequest = (name) => Buffer.concat([slotsFilter(name), subscribeRequest()]);

// SubscribeRequest { watch = 100 { add = 1, remove = 2, clear = 3, id = 4 } }
// addRaw is keys as bytes, of any length.  extra is appended to the
// request next to the watch member.
function watchRequest({ add = [], addRaw = [], remove = [], clear = false, id = 0, extra = null }) {
  const body = Buffer.concat([
    ...add.map((k) => bytesField(1, b58decode(k))),
    ...addRaw.map((k) => bytesField(1, k)),
    ...remove.map((k) => bytesField(2, b58decode(k))),
    ...(clear ? [tag(3, 0), varint(1)] : []),
    ...(id ? [tag(4, 0), varint(id)] : []),
  ]);
  return Buffer.concat([bytesField(100, body), ...(extra ? [extra] : [])]);
}

function decodeUpdate(buf) {
  const u = { filters: [] };
  for (const [f, v] of fields(buf)) {
    if (f === 1) u.filters.push(v.toString());
    else if (f === 2) {
      u.account = {};
      for (const [g, w] of fields(v)) {
        if (g === 2) u.account.slot = w;
        else if (g === 1) for (const [h, x] of fields(w)) {
          if (h === 1) u.account.pubkey = b58encode(x);
          else if (h === 2) u.account.lamports = x;
          else if (h === 6) u.account.dataLen = x.length;
        }
      }
    } else if (f === 100) {
      u.watch = { slot: 0n, accounts: [], more: false, id: 0n, bankId: null, error: null };
      for (const [g, w] of fields(v)) {
        if (g === 1) u.watch.slot = w;
        else if (g === 3) u.watch.more = !!w;
        else if (g === 4) u.watch.id = w;
        else if (g === 5) u.watch.bankId = w;
        else if (g === 6) {
          u.watch.error = { code: 0, message: "", applied: false };
          for (const [h, x] of fields(w)) {
            if (h === 1) u.watch.error.code = Number(x);
            else if (h === 2) u.watch.error.message = x.toString();
            else if (h === 3) u.watch.error.applied = !!x;
          }
        } else if (g === 2) {
          const a = { lamports: 0n, dataLen: 0, executable: false };
          for (const [h, x] of fields(w)) {
            if (h === 1) a.pubkey = b58encode(x);
            else if (h === 2) a.lamports = x;
            else if (h === 3) a.owner = b58encode(x);
            else if (h === 4) a.executable = !!x;
            else if (h === 5) a.dataLen = x.length;
          }
          u.watch.accounts.push(a);
        }
      }
    } else if (f === 6) u.ping = true;
    else if (f === 9) u.pong = true;
    else if (f === 3) u.slot = true;
  }
  return u;
}

// stream

const session = http2.connect(url);
session.on("error", (e) => { console.error("connection error:", e.message); process.exit(1); });
const headers = { ":method": "POST", ":path": "/geyser.Geyser/Subscribe", "content-type": "application/grpc", te: "trailers" };
if (xToken) headers["x-token"] = xToken;
const stream = session.request(headers);

const send = (msg) => {
  const hdr = Buffer.alloc(5);
  hdr.writeUInt32BE(msg.length, 1);
  stream.write(Buffer.concat([hdr, msg]));
};

let pending = Buffer.alloc(0);
let replyWaiter = null;
let replyParts = [];
let seen = new Map(); // pubkey -> { n, firstSlot, lastSlot, names } since the last reset
let total = 0;
let slotUpdates = 0;
let ended = null; // the status the stream ended with

stream.on("data", (chunk) => {
  pending = Buffer.concat([pending, chunk]);
  while (pending.length >= 5) {
    const len = pending.readUInt32BE(1);
    if (pending.length < 5 + len) break;
    const u = decodeUpdate(pending.subarray(5, 5 + len));
    pending = pending.subarray(5 + len);
    if (u.watch) {
      replyParts.push(u.watch);
      if (!u.watch.more && replyWaiter) {
        const parts = replyParts; replyParts = [];
        const w = replyWaiter; replyWaiter = null;
        const last = parts[parts.length - 1];
        w({ slot: parts[0].slot, accounts: parts.flatMap((p) => p.accounts), parts: parts.length,
            ids: parts.map((p) => p.id), bankId: parts[0].bankId, error: last.error });
      }
    } else if (u.slot) {
      slotUpdates++;
    } else if (u.account) {
      total++;
      const e = seen.get(u.account.pubkey) || { n: 0, firstSlot: u.account.slot, names: new Set() };
      e.n++; e.lastSlot = u.account.slot; e.lamports = u.account.lamports;
      for (const n of u.filters) e.names.add(n);
      seen.set(u.account.pubkey, e);
    }
  }
});
stream.on("trailers", (t) => {
  if (t["grpc-status"] && t["grpc-status"] !== "0") {
    ended = t["grpc-status"];
    console.error(`stream ended: grpc-status ${t["grpc-status"]} ${t["grpc-message"] || ""}`);
    process.exit(1);
  }
});
stream.on("response", (h) => {
  if (h["grpc-status"] && h["grpc-status"] !== "0") {
    console.error(`stream refused: grpc-status ${h["grpc-status"]} ${h["grpc-message"] || ""}`);
    process.exit(1);
  }
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Sends a watch edit and resolves with its reply and how long it took.
// What arrives after the reply is counted from zero.
let nextId = 1000;
async function edit(req) {
  const id = nextId++;
  const t0 = process.hrtime.bigint();
  const reply = await new Promise((ok, bad) => {
    replyWaiter = (r) => { seen = new Map(); ok(r); };
    send(watchRequest({ ...req, id }));
    setTimeout(() => bad(new Error("no reply within 10 s")), 10000);
  });
  reply.ms = Number(process.hrtime.bigint() - t0) / 1e6;
  check(reply.ids.every((i) => i === BigInt(id)), `reply carries the request id ${id}`);
  if (!reply.error) check(reply.bankId !== null, `reply carries a bank id (${reply.bankId})`);
  return reply;
}

// Opens another Subscribe stream on the same connection and resolves
// with the status it ends with, or null if it is still open after 2 s.
function secondSubscribe() {
  return new Promise((ok) => {
    const s2 = session.request(headers);
    let status = null, message = "";
    const got = (h) => { if (h["grpc-status"]) { status = h["grpc-status"]; message = h["grpc-message"] || ""; } };
    s2.on("response", got);
    s2.on("trailers", got);
    s2.on("error", () => {});
    s2.on("close", () => ok({ status, message, rst: s2.rstCode }));
    const hdr = Buffer.alloc(5);
    const msg = subscribeRequest();
    hdr.writeUInt32BE(msg.length, 1);
    s2.write(Buffer.concat([hdr, msg]));
    setTimeout(() => { if (!s2.closed) { s2.close(); ok({ status: null, message: "still open", rst: null }); } }, 2000);
  });
}

let failed = 0;
function check(ok, what) {
  console.log(`   ${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) failed++;
}
const short = (k) => k.slice(0, 6);
function showReply(r) {
  if (r.error) {
    console.log(`   reply in ${r.ms.toFixed(2)} ms: error ${r.error.code} "${r.error.message}" applied ${r.error.applied}`);
    return;
  }
  console.log(`   reply in ${r.ms.toFixed(2)} ms: slot ${r.slot}, ${r.accounts.length} account(s)`);
  for (const a of r.accounts) console.log(`     ${short(a.pubkey)} lamports ${a.lamports} data ${a.dataLen} B`);
}
function showSeen() {
  if (!seen.size) { console.log("   updates: none"); return; }
  for (const [k, e] of seen) {
    console.log(`   updates: ${short(k)} x${e.n} slots ${e.firstSlot}..${e.lastSlot} filters [${[...e.names]}]`);
  }
}
// After the settle time, exactly the keys of want were updated.
function checkFlow(want, reply) {
  showSeen();
  for (const k of want) {
    const e = seen.get(k);
    check(!!e, `${short(k)} is updated`);
    if (e) {
      check(e.names.size === 1 && e.names.has("watch"), `${short(k)} updates carry the filter name "watch"`);
      if (reply && reply.accounts.some((a) => a.pubkey === k)) {
        console.log(`     first update of ${short(k)} at slot ${e.firstSlot}, reply was at slot ${reply.slot} (+${e.firstSlot - reply.slot})`);
      }
    }
  }
  for (const k of seen.keys()) check(want.includes(k), `${short(k)} is in the watch set`);
}

const [A, B, C, X] = keys;

console.log(`1. subscribe, no filters, commitment ${arg("commitment", "finalized")}`);
send(subscribeRequest());
await sleep(1500);
check(total === 0, "no account update before the first add");

console.log(`2. add ${short(A)}, ${short(B)}, ${short(X)}`);
let r = await edit({ add: [A, B, X] });
showReply(r);
check(r.accounts.length === 3 && r.accounts[0].pubkey === A && r.accounts[1].pubkey === B && r.accounts[2].pubkey === X,
      "reply carries the added accounts in request order");
await sleep(settleMs);
checkFlow([A, B], r);

console.log(`3. remove ${short(A)}`);
r = await edit({ remove: [A] });
showReply(r);
check(r.accounts.length === 0, "reply carries no account");
await sleep(settleMs);
checkFlow([B], r);

console.log(`4. add ${short(C)}`);
r = await edit({ add: [C] });
showReply(r);
check(r.accounts.length === 1 && r.accounts[0].pubkey === C, "reply carries the added account");
await sleep(settleMs);
checkFlow([B, C], r);

console.log(`5. add ${short(A)} and a key of 31 bytes`);
r = await edit({ add: [A], addRaw: [Buffer.alloc(31, 7)] });
showReply(r);
check(!!r.error && r.error.code === 3 && !r.error.applied, "reply is an INVALID_ARGUMENT error that applied nothing");
check(r.accounts.length === 0, "reply carries no account");
await sleep(settleMs);
check(ended === null, "the stream is open");
checkFlow([B, C], r);

console.log(`6. add ${short(A)} next to a slots filter`);
slotUpdates = 0;
r = await edit({ add: [A], extra: slotsFilter("s") });
showReply(r);
check(!!r.error && r.error.code === 3 && !r.error.applied, "reply is an INVALID_ARGUMENT error that applied nothing");
await sleep(settleMs);
check(ended === null, "the stream is open");
check(slotUpdates === 0, "the filter of the refused request is not installed");
checkFlow([B, C], r);

console.log("7. a slots filter in a request of its own");
slotUpdates = 0;
seen = new Map();
send(slotsRequest("s"));
await sleep(settleMs);
check(ended === null, "the stream is open");
check(slotUpdates > 0, `slot updates arrive (${slotUpdates})`);
checkFlow([B, C], null);

console.log("8. a second Subscribe stream on the connection");
seen = new Map();
const second = await secondSubscribe();
console.log(`   second stream: grpc-status ${second.status} "${second.message}"`);
check(second.status === "8", "the second stream is refused with RESOURCE_EXHAUSTED");
await sleep(settleMs);
check(ended === null, "the first stream is open");
checkFlow([B, C], null);

console.log("9. clear");
r = await edit({ clear: true });
showReply(r);
check(r.accounts.length === 0, "reply carries no account");
await sleep(settleMs);
checkFlow([], r);

console.log(`10. add ${short(A)}`);
r = await edit({ add: [A] });
showReply(r);
check(r.accounts.length === 1 && r.accounts[0].pubkey === A, "reply carries the added account");
await sleep(settleMs);
checkFlow([A], r);

console.log(failed ? `FAIL (${failed} check(s))` : "PASS");
stream.close();
session.close();
process.exit(failed ? 1 : 0);
