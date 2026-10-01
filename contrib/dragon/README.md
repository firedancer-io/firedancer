# Dragon's Mouth harness

Tools for checking what the `dragon` tile serves: against itself, and
against yellowstone-grpc loaded by agave.

| file | what it does |
| --- | --- |
| `capture.py` | subscribes to a Dragon's Mouth endpoint and writes a normalized capture |
| `diff.py` | compares two normalized captures per slot, as multisets |
| `selfcheck.py` | checks the captures of one run against each other (WP7) |
| `churn.py` | opens and closes badly behaved clients, for soak runs |
| `gen_fuzz_seeds.py` | writes the seed corpora of the dragon fuzz targets |
| `filters/*.json` | the subscriptions the harness uses, as protobuf JSON |
| `test_diff.py`, `test_selfcheck.py` | unit tests, `python3 -m unittest` |

`contrib/test/run_dragon_tests.sh` drives the whole thing over a
ledger and is what CI runs (`make run-dragon-tests`).

Everything here needs python 3, `protoc`, and the protobuf runtime
(`python3 -c 'import google.protobuf'`).  `capture.py` speaks HTTP/2
on a raw socket -- no gRPC library -- so it runs anywhere and against
any server that implements the service, which is what makes the oracle
comparison possible at all.  `--zstd` decompresses with the
`zstandard` module when it is installed and shells out to the `zstd`
binary when it is not.

## Browser page

The tile answers an HTTP/1.1 `GET /` on its gRPC port with `index.html`,
which subscribes to transactions over gRPC-Web on the same port and can run
up to 6 clients at once (a browser's limit per host).  Each subscription is
one HTTP/1.1 connection, so it takes one `max_clients` slot.

`gen_index.py` embeds `index.html` into `fd_dragon_index.h`; rerun it after
editing the page.

## Capturing

```
python3 contrib/dragon/capture.py --port 10801 \
    --filters contrib/dragon/filters/accounts.json --commitment finalized \
    --seconds 300 --out /tmp/cap/acct_f
```

A filter spec is a `SubscribeRequest` in protobuf JSON, so every field
of the request surface is reachable: all six filter maps, `entry`,
`commitment`, `accounts_data_slice`, `ping`, `from_slot`.  `bytes`
fields are base64, as protobuf JSON requires; account memcmp filters
also take `base58` and `base64` strings, which is usually easier:

```json
{ "accounts": { "vote": {
      "owner": ["Vote111111111111111111111111111111111111111"],
      "filters": [ { "memcmp": { "offset": 0, "base58": "3J98t1" } },
                   { "datasize": 3762 } ] } },
  "accounts_data_slice": [ { "offset": 0, "length": 32 } ],
  "commitment": "FINALIZED" }
```

`--commitment` on the command line overrides the spec, so one spec
serves every level.  `--token` sets `x-token`, `--zstd` asks for zstd
and decompresses what comes back, `--from-slot` exercises the
`out_of_range` reply.  A run stops on `--seconds`, on `--until-slot N
--until-status finalized`, or on `--idle-timeout`; it answers the
server's pings with a pong, and on a lost connection it reconnects
once and records the gap.

Four files come out of a run:

| file | contents |
| --- | --- |
| `<out>.bin` | the response messages as they arrived, gRPC framed and decompressed |
| `<out>.jsonl` | one normalized record per update, except slot statuses |
| `<out>.slots.jsonl` | one normalized record per slot status |
| `<out>.meta.json` | counts, stop reason, response headers and trailers, gaps |

`<out>.bin` is a plain stream of gRPC length-prefixed
`SubscribeUpdate`s -- the same thing `curl --output` writes -- so any
capture taken with another client can be normalized after the fact:

```
python3 contrib/dragon/capture.py --decode-only stream.bin --out /tmp/cap/stream
```

Decoding is always a second pass over `<out>.bin`.  The live loop only
parses HTTP/2 frames, which keeps it well ahead of the server even at
tens of megabytes a second; a decoder that cannot keep up would
otherwise be closed as a lagged subscriber and the capture would be
the tool's fault rather than the tile's.

### Normalization

Per plan section 8, a record is

```json
{"seq": 12, "slot": 424669011, "kind": "account", "key": "3xTp...",
 "payload": { ... }, "nondet": { ... }}
```

* `kind` is `account`, `transaction`, `transaction_status`, `block`,
  `block_meta`, `slot` or `entry`; pings and pongs are counted in
  `meta.json` and are not records.
* `key` identifies the subject within its slot: pubkey, signature,
  blockhash, or the status name.
* `payload` is everything a comparison may look at.  Pubkeys,
  signatures, owners and hashes are base58; account data, instruction
  data and error blobs are hex; absent optional fields are `null`;
  keys are written in sorted order.  Lists whose order is not
  meaningful (a block's transactions, accounts and entries) are sorted
  by index or pubkey, so that two servers that emit them in different
  orders still compare equal.
* `nondet` holds what depends on which server produced the stream and
  when -- `created_at`, `bank_id`, `write_version` -- so it is out of
  `payload` and no diff ever sees it.  `selfcheck.py` does use
  `write_version`, which is why the capture keeps it rather than
  dropping it on the floor; `--no-nondet` drops it anyway.
* `seq` is arrival order, for ordering checks; it is not compared.
* `filters` (the names the server echoed) is a payload field, so it is
  compared unless masked with `--ignore filters`.

## Diffing

```
python3 contrib/dragon/diff.py oracle.jsonl subject.jsonl \
    --label-a yellowstone --label-b dragon \
    --drop-startup-a --common-slots --skip-first 1 --skip-last 1
```

Within a slot each side is a multiset of `(kind, key, payload)`:
delivery order inside a slot is nondeterministic on both sides, and a
repeated update is a real difference, which is what a multiset -- and
not a set -- captures.  The report gives, per slot, what is only in A,
what is only in B, and for a `(kind, key)` on both sides with a
different payload, the leaf fields that differ.  Exit code 0 when the
compared slots match.

Masks:

| option | what it is for |
| --- | --- |
| `--ignore NAME` | drop the field NAME at any depth on both sides (`rent_epoch`, `cost_units`, `filters`) |
| `--drop-startup-a` | drop the oracle's startup account dump, which a live subscription has no counterpart for |
| `--kind K` | compare only these kinds (the oracle emits accounts and transactions only) |
| `--common-slots`, `--slots lo:hi`, `--skip-first`, `--skip-last` | bound the window to what both sides could have seen |

The windows are not cosmetic: the first bank is already executing when
a subscription opens, so its content is partial on whichever side
connected later, and the last slots of a run are unrooted on one side
and absent on the other.

## Self-consistency (WP7)

On a fork-free ledger the finalized content of a slot *is* its
processed content deduped per account to the last write, so one run
carries its own oracle.  `selfcheck.py` takes the captures of a single
run and asserts that:

* the transactions of a slot at a deferred level are the same
  multiset, with the same meta, as at processed;
* `index` is dense from zero;
* the accounts at a deferred level are the processed writes deduped to
  the last one per pubkey, with that write's state, and no pubkey
  twice;
* `BlockMeta.executed_transaction_count` is the number of transactions
  the slot delivered, and a slot has one block meta;
* a block carries exactly its slot's transactions and accounts, and
  its counts agree with what it carries;
* the statuses of a slot arrive in order, every rooted slot is
  finalized exactly once, finalized slots arrive ascending, and every
  rooted slot in the served range has content.

```
python3 contrib/dragon/selfcheck.py \
    --level processed=$C/txn_p --level processed=$C/acct_p \
    --level finalized=$C/txn_f --level finalized=$C/acct_f \
    --level finalized=$C/blocks_f --slots $C/slots --metrics $C/../metrics.txt
```

### Truncated records are never tolerated silently

A commit record that named the accounts a transaction wrote but could
not carry their data (`accounts_truncated`, `fd_event_internal.c:201`)
is skipped at processed -- the tile counts it in
`dragon_account_skipped_total` -- and served at a deferred level from
the accounts database instead (`fd_dragon_rpc.c:1663`,
`fd_geyser_core.c:1308`).  Two things follow, and both would look like
a bug to a naive comparison: an account can be at finalized and not at
processed, and an account's last *processed* state can be older than
the state at finalized.

The reconciliation is per record and does not depend on when a
counter was scraped.  The tile logs one line per truncated record,

```
dragon truncated record: slot 424669010 bank 424669010 index 3 accounts 7
```

and `--truncated-log` (the runner passes the dragon log) is what
`selfcheck.py` checks the difference against: every unexplained
account must be in a slot that has a truncated record, no slot may
have more of them than its records wrote, and the totals must agree.
Anything else is a FAIL, including an unexplained account with an
empty log.  The count is under the accounts the records wrote when one
of them was written again in the same slot by a record that fit, which
is a WARN.

`dragon_account_skipped_total` is kept as a second, WARN-only check:
it is a scrape of a running tile and can be taken before the last
truncated record of the run, so it can only corroborate the log, never
fail a run.  With no `--truncated-log` at all the tool falls back to
the counter and fails when there is nothing to reconcile against.

Accounts written at processed and *missing* at finalized are always a
FAIL: truncation never explains those.

## The CI job

```
make run-dragon-tests                       # the CI ledger
DUMP=/path LEDGER=... END_SLOT=... OUT=/path contrib/test/run_dragon_tests.sh -nr
```

The script replays the ledger twice, once without the dragon tile and
once with it, runs eight capture clients against the second run (slots,
transactions and accounts at processed and finalized, block metas at
both, blocks at finalized), scrapes the metrics, and then:

| criterion | fails when |
| --- | --- |
| replay | the backtest exits non-zero, or logs `Bank hash mismatch` |
| bank hashes | the `slot=..., hash=...` set differs from the run without dragon |
| captures | a capture produced no metadata or no messages |
| self-consistency | `selfcheck.py` reports a failing check |

The hash comparison is the point of the baseline run: everything the
tile does on the execution path has to be invisible to consensus.
`SKIP_BASELINE=1` skips it (and the check), which is what a second
dragon run for a capture-to-capture diff wants.

## The oracle comparison (plan section 8)

Oracle = yellowstone-grpc v16 loaded by `agave-ledger-tool verify
--geyser-plugin-config` (`ledger-tool/src/main.rs:921`).  Subject =
`firedancer-dev backtest` with dragon enabled.  The same `capture.py`
connects to both, so the two captures are normalized identically and
`diff.py` compares them directly.

`contrib/dragon/oracle/run_oracle.sh` runs the oracle side;
`ORACLE=1 contrib/test/run_dragon_tests.sh` runs the subject and the
diffs.  Both are off by default, so the CI job is unchanged.

### 1. Build the plugin and the ledger tool

The vendored protos come from yellowstone-grpc tag
`v16.0.0-rc8+solana.4.3.0.rc.0` (see `proto/README.txt`), which pins
agave 4.3.0-rc.0.  The plugin must be built against that same agave
tree, or the geyser plugin interface will not match and
`agave-ledger-tool` will refuse to load it.  In 4.3 the ledger tool
lives in its own `dev-bins` workspace.

```
git clone https://github.com/rpcpool/yellowstone-grpc
cd yellowstone-grpc && git checkout v16.0.0-rc8+solana.4.3.0.rc.0
cargo build --release -p yellowstone-grpc-geyser -p yellowstone-grpc-client-simple
# target/release/libyellowstone_grpc_geyser.so, target/release/client

cd <agave>/dev-bins
CARGO_TARGET_DIR=<somewhere> cargo build --release -p agave-ledger-tool
```

### 2. Run it

```
YELLOWSTONE_SO=.../libyellowstone_grpc_geyser.so \
LEDGER_TOOL=.../agave-ledger-tool \
ORACLE=1 DUMP=<dump> LEDGER=<ledger> END_SLOT=<N> OUT=<out> \
  contrib/test/run_dragon_tests.sh -nr
```

`ORACLE_CAPTURE=<dir>` reuses an oracle capture instead of replaying
the ledger again; `ORACLE_STRICT=1` makes a surviving difference fail
the run; `ORACLE_ACCOUNTS_FULL=1` adds a subscription to every
account's whole data (see "what does not fit in a backtest" below).

`run_oracle.sh` replays a *copy* of the ledger.  Two things make that
necessary: with a read-only blockstore the ledger tool puts its bank
snapshots and accounts under `<ledger>/ledger_tool` whatever the
command line says (`ledger_utils.rs:144-151,240-248`), and the
transaction status service writes block time, block height and rewards
for every frozen bank whether or not `--enable-rpc-transaction-history`
is given (`transaction_status_service.rs:279-318`), so it needs a
read-write blockstore and dies on a read-only one.  The copy is a
reflink where the filesystem has them.

Two flags are not optional on a perf ledger:

* `--use-snapshot-archives-at-startup when-newest` asks for the
  read-write blockstore the transaction status service needs
  (`ledger_utils.rs:620-624`).
* `--limit-load-slot-count-from-snapshot 100000000` is above the number
  of storages in any snapshot, so it loads all of them, and it is what
  turns the capitalization and accounts-lt-hash checks of
  `snapshot_bank_utils.rs:226,268` into warnings.  A perf ledger carries
  a *minimized* snapshot whose lt hash is the one of the full state it
  was minimized from, so those checks fail on a snapshot that is
  perfectly good for replaying its own slot range.

### 3. What the oracle can and cannot see

Offline agave wires up only two of the geyser callbacks
(`ledger-tool/src/ledger_utils.rs:277-290`): the accounts update
notifier, and the transaction notifier behind the transaction status
service.  There is no slot status notifier, no entry notifier and no
block metadata notifier, and the confirmed bank sender is dropped, so
yellowstone never seals a bank.  Measured on a 596-slot mainnet
replay, the six oracle subscriptions received:

| stream | messages |
| --- | --- |
| `accounts` (all) | 2,032,653 |
| `transactions` (all) | 688,817 |
| `transactions_status` (all) | 688,817 |
| `slots` | 0 |
| `blocks_meta` | 0 |

No `is_startup` accounts either: `snapshot_plugin_channel_capacity`
defaults to null, which drops the snapshot channel, and offline agave
has no startup dump to send anyway.  The comparison is therefore
**processed only, on accounts and transactions**; the finalized path is
validated by `selfcheck.py`, the unit tests in the WP7 table below, and
a live side-by-side.

The two sides do not have to be the same ledger directory, only the
same blocks and the same starting state.  The check that says so is the
bank hashes: on the run below, agave's 596 frozen bank hashes for
424669001..424669600 are identical to Firedancer's, which is what makes
every difference below a reporting difference rather than an execution
one.

### 4. What the diff found

Run of 2026-09-14 on `mainnet-424669000-perf-ledger`, slots
424669001..424669600, 591 slots compared (`--common-slots --skip-first
1 --skip-last 1`; the three slots the subject missed are the ones
already replaying when its subscriptions opened).

| stream | oracle | dragon | verdict |
| --- | --- | --- | --- |
| `transactions_status` | 688,817 | 685,885 | **identical** |
| `transactions` | 688,817 | 685,885 | identical except two fields, below |
| `accounts`, 32-byte data slice | 2,032,653 | 2,341,664 | 364 differ, 315,774 extra, 77 missing |
| `accounts`, whole data, token program owner | 282,635 | 396,327 | **every shared update identical**, 113,957 extra |

With `--ignore pre_token_balances --ignore post_token_balances
--ignore log_messages`, the transaction stream matches **exactly**: the
683,156 transactions the 591 compared slots have on both sides, zero
differing payloads, nothing on one side only.  That covers the error
bincode bytes, the fee, both balance vectors, inner instructions with
their `stack_height`, loaded addresses, return data, compute units,
`index`, `is_vote`, and the whole `Transaction` message down to
`address_table_lookups` and the legacy/V0 discriminant.

What the two masks hide, and everything the account streams report:

1. **`pre/post_token_balances` are always empty** (D15, out of dragon's
   scope until a shared `fd_txn_meta` effort lands them).  117,751 of
   the 683,156 compared transactions carry them on the oracle side.
2. **Transaction logs**, 1,709 transactions, all of it pre-existing
   runtime behaviour that the oracle merely surfaces:
   * 1,135 differ only in the per-program `consumed N of M compute
     units` number, and always by **exactly 8 CU per invocation**:
     Firedancer logs the meter delta
     (`fd_bpf_loader_program.c:531`), agave logs what rbpf returned
     from `execute_program` (`program-runtime/src/vm.rs:317,347-352`).
     The transaction-level `compute_units_consumed` agrees.
   * 571 carry two extra lines per precompile instruction:
     Firedancer logs `Program <precompile> invoke [1]` and `success`
     (`fd_executor.c:1230`), agave runs precompiles through
     `InvokeContext::process_precompile`, which logs nothing
     (`program-runtime/src/invoke_context.rs:516-520,618-631`).
   * 3 shorten a VM failure: `Access violation` where agave writes
     `Access violation writing 8 bytes at address 0x... (in unallocated
     memory)`.
3. **315,774 account updates dragon sends and agave does not** (+15.6%),
   every one of them on a transaction that succeeded.  Agave stores a
   writable account only if a program mutably accessed it
   (`touched_flags`, `runtime/src/account_saver.rs:121-124`,
   `transaction-context/src/instruction_accounts.rs:359`) and not if it
   is invoked without being an instruction account
   (`account_saver.rs:126-133`); Firedancer marks every writable
   acquired account for commit (`fd_runtime.c:1162-1176`).  Closing
   this needs a `touched` flag in `fd_acc_t`, which is a runtime
   change.
4. **364 closed accounts report the wrong owner and no data.**
   `fd_runtime_lthash_account` clears `data_len`, `executable` and
   `owner` on the account object before hashing it
   (`fd_runtime.c:1124-1128`) and the commit record is built from that
   object afterwards, so a zero-lamport account arrives owned by the
   system program with empty data where yellowstone reports what the
   program left behind.  The fix belongs in the runtime: hash the
   tombstone from locals instead of writing it into the account.
5. **77 accounts the oracle has and dragon does not** are the truncated
   records of the section above -- skipped at processed, served at
   finalized -- and `selfcheck.py` reconciles all 77 against
   `dragon_account_skipped_total`.

Nothing else survives.  In particular `rent_epoch` never differs over
2.03M account updates, which closes the plan's open question about
whether agave writes `RENT_EXEMPT_RENT_EPOCH` on every stored account.

One dragon bug came out of this run and is fixed:
`fd_event_internal_post_lamports` now reports the balances a *failed*
transaction leaves behind.  A failed transaction writes back only its
rollback accounts, and agave collects its post balances after that
write-back (`svm/src/transaction_processor.rs:612-626`), but the
account objects the record is built from still carried what execution
had done to them, so 26,691 transactions reported post balances for
writes that were rolled back.  `test_dragon_records.c:test_post_lamports`
pins the rule down.

### What does not fit in a backtest

A backtest replays several times faster than the cluster produces
blocks -- 596 mainnet slots in about 45 seconds, roughly six times real
time -- so a subscriber sees six times the byte rate it would see live.
A subscription to every account's *whole* data is 15 GiB over those 45
seconds, about 375 MB/s, which no client here can take: `capture.py`,
and `curl` writing straight to tmpfs, are both closed with
`lagged to send an update` long before the replay ends.  Yellowstone
absorbs the same burst because it buffers whole messages
(`channel_capacity`, 250k by default) where the dragon tile has a fixed
per-stream byte queue.

That is a property of the harness, not of the tile: live, the same
subscription is about 60 MB/s.  Two ways around it, both used above:

* compare the 32-byte data slice of `filters/accounts.json` over every
  account, which is what `ORACLE=1` does by default, and
* compare the *whole* data of a bounded population --
  `filters/accounts_token_full.json` is every SPL token account, 282,635
  updates and 42 MB of account data over the same 596 slots -- which is
  where the "every shared update identical" line of the table comes
  from.

### Dry runs

Two things can be proven without an oracle, and both are part of the
deliverable:

1. **Two dragon runs of the same ledger diff clean.**  Run
   `run_dragon_tests.sh` twice with different `OUT` and
   `SKIP_BASELINE=1`, then diff the two processed captures.  They
   agree everywhere except the first bank (in flight when the
   subscription opened, so partially captured, and at a different
   point in each run) and the bank in flight when each run stopped.
   `--common-slots --skip-first 1 --skip-last 1` is what takes those
   out; that the rest is identical is what says the capture path
   itself is deterministic and the comparison is measuring the server
   rather than the client.

2. **Processed against finalized, with the documented masks.**  This
   is the same shape as the oracle diff -- two captures of different
   provenance -- and it exercises `--ignore`.  Accounts differ
   legitimately because processed carries every write and finalized
   only the last, so the honest form of this check is
   `selfcheck.py`; as a diff it is run on transactions, where the two
   levels must agree exactly:

   ```
   python3 contrib/dragon/diff.py $C/txn_p.jsonl $C/txn_f.jsonl \
       --label-a processed --label-b finalized --common-slots --skip-first 1
   ```

## The leader path

Every backtest replays blocks another validator produced, so it
exercises the `execrp` tiles and never the `execle` ones: `is_leader`
records and the `index_in_slot` of a block this validator built are
not covered by `run_dragon_tests.sh`.  The links are wired for both
(`src/app/firedancer/topology.c:214-250` gives `execrp`, `execle` and
`replay` an `<tile>_evint` link into dragon), so what is missing is a
run in which Firedancer is the leader.

A single node cluster does that, and needs no agave: firedancer-dev
creates its own genesis with the node as the bootstrap validator when
no gossip entrypoint is configured.

```
firedancer-dev keys new "$BASE/vote-account.json"          # the keys stage does not
firedancer-dev configure init keys genesis --config dev.toml
firedancer-dev dev --no-configure --no-watch --config dev.toml
python3 contrib/dragon/capture.py --port <dragon port> \
    --filters contrib/dragon/filters/transactions.json --out /tmp/leader
```

`dev.toml` wants `[gossip] entrypoints = []` (which is what selects
bootstrap mode and genesis creation), `[net] provider = "socket"`, and
a `[layout] affinity` that only names CPUs the process may run on.

As of this branch the run reaches slot 31 as leader ("becoming leader
for slot 31") and then the replay tile aborts:

```
fd_accdb.c(792)[fd_accdb_attach_child]: FAIL: acquired
  (accdb fork pool exhausted after deferred drain)
```

The same abort happens at the same slot with `[tiles.dragon] enabled =
false`, so it is not the dragon tile: the cluster has not rooted
anything by slot 31 (`root_slot=18446744073709551615` in the tower
log) and the accdb fork pool, sized from `[runtime] max_live_slots`,
runs out first.  Twelve seconds of leader slots is not enough for a
subscriber to see a block, so `is_leader` records and leader
`index_in_slot` density remain unverified.  What would close it: a
local cluster that survives its first root -- a larger
`max_live_slots`, or whatever fix the fork pool exhaustion needs --
and then the capture above.

## WP7 checklist

Every bullet of WP7's unit-test deliverable, and the test that covers
it.  `test_geyser_core` is the fork graph and commitment machine,
`test_dragon_rpc` the store, filters and delivery.

| WP7 bullet | test |
| --- | --- |
| dedup to the last write (3 writes → 1 update) | `src/discof/dragon/test_dragon_rpc.c:test_acct_dedup` |
| +10/−10 still emitted | `src/discof/dragon/test_dragon_rpc.c:test_acct_dedup` (the account ends where it started and is still reported) |
| mask eligibility from the next new bank | `src/discof/dragon/test_dragon_rpc.c:test_defer_delivery` |
| quarantine of disconnected slots | `src/discof/dragon/test_dragon_rpc.c:test_defer_quarantine` |
| filter update clears in-flight bits | `src/discof/dragon/test_dragon_rpc.c:test_defer_filter_update` |
| delivery order (data → `Block` → `BlockMeta` → `Slot`) | `src/discof/dragon/test_dragon_rpc.c:test_defer_order` |
| ancestors ascending on `ROOT_ADVANCED` | `src/discof/dragon/test_geyser_core.c:test_root_ancestors` |
| losers discarded on `OC_ADVANCED` | `src/discof/dragon/test_geyser_core.c:test_equivocation_oc` |
| incomplete bank ⇒ nothing at the level | `src/discof/dragon/test_geyser_core.c:test_incomplete_suppressed`, `src/discof/dragon/test_dragon_rpc.c:test_defer_incomplete` |
| `DROP_BANK_REF` ⇒ immediate release | `src/discof/dragon/test_geyser_core.c:test_drop_bank_ref`, `src/discof/dragon/test_dragon_rpc.c:test_acct_drop_bank_ref` |
| `bank_seq` reset | `src/discof/dragon/test_geyser_core.c:test_bank_seq_reset` |
| stale sweep | `src/discof/dragon/test_geyser_core.c:test_stale_sweep` |

The backtest half of WP7 is `contrib/test/run_dragon_tests.sh`; the
live side-by-side on testnet is the remaining piece and needs a
machine with a network.
