# Skip and missed-vote probe build (testnet, Alpenglow)

For a Claude instance setting up a second diagnostic node on another box. This branch is
`origin/main` (a012dcf2f9) plus log-only probes. **Never merge or cherry-pick it into main.**
The probes only emit `FD_LOG_NOTICE` lines that start with `probe `: no new files, syscalls,
or tile state beyond a few statics, so the sandbox is unchanged.

Goal: every missed vote and every skipped leader slot of our node gets a per-slot timeline
built from these lines plus the ClickHouse events DB.

## 1. Build

```bash
git fetch origin chali/probes/skip-diag
git worktree add --detach ~/fd-probe origin/chali/probes/skip-diag   # or a plain checkout
cd ~/fd-probe
./deps.sh                 # first time on the box: submodules, system packages, ./opt
make -j firedancer-dev
BIN="$(make --silent objdir)/bin/firedancer-dev"
```

- Check `make`'s exit status. The build uses -Werror, so a warning is a failure.
- In a worktree, `opt/` has to exist (a symlink to a checkout that already ran
  `deps.sh`). Otherwise the link fails with a misleading OpenSSL error.
- Only one build at a time per box.

## 2. Config

Run with `--testnet`, which layers `src/app/firedancer/config/testnet.toml` (entrypoints,
genesis hash, `shred_tile_count = 4`, `[development] alpenglow = true`) under your own file.
The reference node's own file is only:

```toml
[paths]
    base = "/data/<you>/firedancer-testnet"      # ledger/accounts; needs lots of space
    identity_key = "/path/to/identity.json"
    vote_account = "<vote account pubkey>"

[development]
    core_dump = "full"
    alpenglow = true

[tiles]
    [tiles.gui]
        gui_listen_address = "0.0.0.0"
    [tiles.metric]
        prometheus_listen_address = "0.0.0.0"
```

**Identity: use a key no other running validator uses.** If two nodes run the same identity,
duplicate-instance detection kills one of them. The reference node runs 9GpHcZ, and so did
val201 at one point, whose auto-restart repeatedly killed the reference node. Ask the operator
which identity and vote account this box gets.

- A **staked identity that has a BLS key (VAT-onboarded)** votes. You get the full vote,
  reward-ACK and leader probes.
- An **unstaked identity** does not vote and never leads. You still get the pool, tally,
  timeout-state, chainer and replay probes, which covers most of the skip diagnosis for
  other leaders.

## 3. Launch

It has to survive the Claude session. Children of a session's background shell get SIGTERM
when the session ends, so use `setsid nohup`:

```bash
cd /data/<you>          # NOT the repo root: an untracked keypair file named like the vote
                        # account in the repo root makes configure fail
setsid nohup sudo -E "$BIN" --config /path/to/testnet.toml --testnet --no-clone \
  > /dev/null 2> /data/<you>/testnet-node.err < /dev/null &
```

- **Find the pid** of the real process, not the sudo wrapper:
  `ps -eo pid,args | grep "$BIN --config" | grep -v sudo`.
- **Log:** `/tmp/fd-0.1.1_<pid>_*GMT*`, one file per process.
- **Stopping:** `sudo kill -TERM <pid>`. It exits cleanly within about a second.
- **After launch,** watch for exit or ERR/CRIT without narrating routine lines:
  ```bash
  until [ ! -d /proc/$P ] || grep -qE '^(ERR|CRIT)' $L; do sleep 2; done
  ```
- **Catch-up:** takes about 2 min from snapshot. Right after boot there's a one-time burst of
  about 700 `probe leader: lost window` lines. That's catch-up, not real losses.

## 4. Persist probe lines

`/tmp` gets cleaned, so tail the log into a durable index (detached):

```bash
mkdir -p ~/missed-votes/index
cat > ~/missed-votes/extract.sh <<'EOF'
#!/bin/bash
P=$1
L=$(ls /tmp/fd-0.1.1_${P}_*GMT* 2>/dev/null | head -1)
[ -n "$L" ] || { echo "no log for pid $P" >&2; exit 1; }
exec tail -n +1 -F "$L" | grep --line-buffered 'probe ' >> ~/missed-votes/index/probe-${P}.log
EOF
chmod +x ~/missed-votes/extract.sh
(setsid nohup ~/missed-votes/extract.sh <pid> > ~/missed-votes/extract-<pid>.err 2>&1 < /dev/null &)
```

It writes about 25 lines/s in steady state, roughly 1.5 GB/day. Restart the extractor after
every bounce, because the pid changes.

## 5. Probe reference (all `NOTICE`, grep `probe `)

The timestamp on each log line is UTC wallclock. Report times to Chali in **CT (America/Chicago)**.

### Rewards and our votes
- **`probe rcert:`** (replay) Every replayed block's footer reward certs:
  - Format: `block S bid B parent P pbid PB leader L own 0|1 reward_slot R reward_epoch E our_rank K footer 0|1 notar ... nset HEX skip ... sset HEX`.
  - HEX is the `fd_bls_set` words (each `%016lx`); bit k of word k>>6 is rank k.
  - **R is rewarded for us iff our rank is set in nset ∪ sset of the *finalized* block at R+8.**
    This footer is the source of truth, not the GUI or RPC.
- **`probe rankmap:`** Once per reward epoch: `epoch E rank K identity I vote V stake S` per ranked validator.
- **`probe root:`** `slot S bid B` on every consensus-root advance. Walk parent/pbid links from
  these to get the finalized chain; a slot missing from the chain inside a walked interval was skipped.
- **`probe own vote:`** Every vote we cast:
  - Format: `kind K slot S rank R bid B reason N finalized F pool P sent N txfail N leader8 L l8conn C l8tx N`.
  - kind: 0 notar, 1 final, 2 skip, 3 notar_fb, 4 skip_fb.
  - reason: 0 block_replayed, 1 parent_ready, 2 block_notarized, 3 timeout, 4 safe_to_notar,
    5 safe_to_skip, 255 standstill rebroadcast.
  - l8conn: -1 unknown leader, 0 no peer, 1 no conn, 2 not active, 3 active.
- **`probe rva:`** Reward-vote ACK tracking to the R+8 leader:
  - Format: `slot S kind K leader L event track|send|retransmit|ack|overwrite|unacked|noconn|txfail|untracked ...`.
  - `ack` carries `try`, `lat_us` and `rtt_us`.
- **`probe pack:`** Reward certs our own leader packed, with signer counts.
- **`probe quicm:`** QUIC client/server counter deltas every 10 s.

### Skip diagnosis
- **`probe pool: ev ...`** Every pool event:
  - `parent_ready slot S parent P pbid B finalized F next_leader N`
  - `safe_to_notar slot S hash H`
  - `safe_to_skip slot S`
  - `cert kind K slot S hash H` (K: 0 final, 1 fast_final, 2 notar, 3 notar_fallback, 4 skip)
  - `standstill slot S certs C votes V`
- **`probe tally:`** Pool stake for a slot at safe_to_notar/safe_to_skip, at every non-final cert,
  and when our timeout fires:
  - Format: `total top_notar top_hash notar_or_skip skip skip_fb final cert_notar cert_nfb cert_skip cert_ff cert_final parents sent_s2s finalized`.
  - Tells you whether a skipped block had partial notar support or nobody saw it.
- **`probe timeout:`** Our skip timer fired for slot S:
  - `action`: `skip_window`, `none_voted`, `ignored_finalized` or `ignored_retired`.
  - Also logs voted, voted_notar, `pending` (block replayed but parked), parents_ready count,
    notarized, bad_window.
- **`probe votor: slot S pending ... why W`** Why we did not notar a replayed block:
  - `no_key`, `no_parent_ready`, `parent_ready_other_parent`;
  - `parent_not_prev_slot`, `parent_not_voted`, `parent_voted_skip`, `parent_hash_mismatch`.
- **`probe votor: slot S replay ignored ...`** Replay finished after the slot was pruned or retired.
- **`probe votor rx replay:`**, **`probe replay start:`**, **`probe replay done:`** Replay timeline per block.
- **`probe replay stall:`** txncache attach/finalize took >100 ms.
- **`probe votor repair:`** Every block the pool asked rotor to fetch.
- **`probe chainer:`** When rotor prunes slots at root advance, one line per block version:
  - Format: `bid rooted turbine abandoned parent pbid connected complete_idx buffered_idx delivered_idx last_fec turbine_cnt repair_cnt recovered_cnt parity_cnt first_shred_ts last_shred_ts req_* repair_resp first_req_ts last_resp_ts`
    (timestamps are wallclock ns).
  - `slot S none` means no shred of S ever arrived.
  - This is the only record of reception for slots that never completed.

### Our own leader slots
- **`probe leader: publish slot S parent_slot P parent_block_id B finalized F highest_parent_ready H waited_us W`**
  The `fd_votor_leader_t` frag votor sends replay.
- **`probe leader: waiting slot S`** The first check that found no ParentReady.
- **`probe leader: lost window slot S finalized F`** Finalization passed our window before ParentReady.
- **`probe replay leader rx:`** The same frag as replay received it, plus what it overwrote
  (`prev_next_leader`, `is_leader`, `reset_slot`, `consensus_root`).
- **`probe replay leader blocked: slot S parent_slot P why W since_us T`** Logged on every change of blocker:
  - `parent_block_id_unknown`, `parent_bank_gone`, `parent_not_frozen`;
  - `banks_full`, `halt_leader`, `no_leader_support`.
- **`probe replay leader start: slot S parent_slot P blocked_us T last_block W`**
- **`probe replay leader cancel: slot S parent_slot P finalized F`** The root passed our parent before we started.
- ClickHouse `events.block_completed` rows with `is_leader=1` add pack start/end, shred counts and cost.

### Diagnosing one skipped slot S (leader L)
```bash
I=~/missed-votes/index/probe-<pid>.log
grep -E "slot $S( |$)|block $S |parent_slot $((S-1)) " $I      # everything about S
grep -E "probe (pool: ev parent_ready|leader|replay leader).* $W" $I   # W = window start (S - S%4)
```
Read it in this order:
1. **Chainer line:** did shreds arrive? How many from turbine vs repair, and when?
2. **replay start/done:** did we replay it, and how late?
3. **`votor ... pending why`:** did we decline to notar, and why?
4. **`timeout`:** state when our timer fired.
5. **`tally`:** did anyone else notar it?
6. **`pool: ev cert`:** order and time of the skip or notar certs.

For our own leader window, also read: `leader publish` → `replay leader rx` → `blocked`/`start`/`cancel`,
then ClickHouse `block_completed` (is_leader=1) and the other FD nodes' `first_shred_received_time` for it.

## 6. ClickHouse events DB

Every FD node on testnet reports `events.alpenglow_vote`, `events.alpenglow_cert` and
`events.block_completed` there. `fd.leader_schedule` has the schedule.

- **Credentials** are environment variables `CH_*` / `GRAFANA_*`. Ask the operator for them.
  Never write them to a file or print them.
- **Duplicate certs** are dropped from `alpenglow_cert`. The collector can also stall, so a
  missing row is not proof of absence.
- **Before blaming a stall,** check the probe index.

## 7. Rules for this work
- **Report times** in CT, and only for the current run (header: pid, CT start, slot range covered).
- **Diagnose each miss or skip on its own, maximally.** Give a timeline per slot, never a
  category count. State the data cutoff, and list every excluded category (boot catch-up,
  skipped R+8).
- **No bounces** unless Chali asks. Don't rebuild into the worktree of the running binary.
- **No GitHub writes** (comments, PRs, pushes) unless Chali explicitly asks for that exact action.
