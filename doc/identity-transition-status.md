# Identity transition observations

Native Firedancer exposes the parameterless HTTP JSON-RPC method
`identityTransitionStatus` when the RPC tile is enabled. It uses the
version-1 Agave identity transition response shape. Omitted parameters,
`null`, and `[]` are accepted; arguments and object parameters are rejected.

This is an observation of the most recent admitted identity command, not
a command, finality check, or failover policy. Existing admin validation,
switch acknowledgements, return values, consensus rules, vote history
handling, signing, connection management, and persistence remain unchanged.
Frankendancer does not expose this observation.

## Response

| Field | Meaning |
| --- | --- |
| `version` | `1` |
| `processInstanceId` | Opaque identifier generated when the admin tile starts. Changes on restart. |
| `sequence` | Starts at zero; increases for each admitted identity command in that instance. |
| `state` | `idle`, `transitioning`, `complete`, or `failed` |
| `consensus` | `unknown`, `tower`, or `alpenglow` |
| `currentIdentity` | Published RPC identity, as returned by `getIdentity`. May change while transitioning. |
| `fromIdentity` | Identity before the command |
| `toIdentity` | Requested identity |
| `voteAccount` | Configured vote account; empty until a successful transition provides the metadata, or if no account is configured. |
| `fromIdentityLastSubmittedVoteSlot` | Frozen maximum slot successfully accepted by the local outbound path under the outgoing identity, or `null` when no such submission was observed. |
| `towerRootSlot` | Outgoing local Tower root at its existing switch boundary, or `null`. Always `null` under Alpenglow. |
| `error` | Observation error string, or `null` |

Before the first admitted command, state is `idle`, sequence is zero,
consensus is `unknown`, and both transition identities are the startup
identity. While `transitioning`, submission and root evidence are `null`.
The response is a coherent snapshot of the transition record; the RPC
identity is read separately from the RPC tile's own published identity.

The instance/sequence pair identifies an observation. Query the source
validator after its command and verify the instance, sequence, outgoing
and requested identities, and `complete` state. A later command replaces
the record; there is no transition history. Rejected commands leave it
unchanged. A busy or uninitialized snapshot returns JSON-RPC error -32603.

## Existing switch boundaries

Tower:

```text
identity command admitted
        |
        +-- publish transitioning (slot = null)
        |
        v
Replay pauses and adopts requested identity
        |  observe rooted bank / consensus
        v
Tower consumes Replay's existing sequence boundary
        |  existing signing halt and publication flush
        |  freeze outgoing Tower root and vote account
        v
TxSend consumes Tower's existing sequence boundary
        |  votes accepted during this flush still count
        |  freeze outgoing maximum submitted slot S
        v
existing Gossip / signer / other tile switches and resume
        |
        v
existing admin command completes successfully
        |
        +-- publish complete (fromIdentityLastSubmittedVoteSlot = S)
```

Full Alpenglow:

```text
identity command admitted -> transitioning (slot = null)
        |
Replay pauses -> observe rooted full Alpenglow evidence
        |
Votor consumes Replay's existing sequence boundary
        |  existing BLS signing halt
        |  existing queued vote / pool event flush
        |  own broadcasts and reward retries accepted before switch count
        |  freeze outgoing maximum submitted slot S
        |  existing connection switch and reward cache clear
        v
existing other tile switches / resume / wait-to-vote rules
        |
existing admin command succeeds -> complete (slot = S)
```

Completion is published after the existing command succeeds and matching
Replay and voter observations (plus TxSend under Tower) have frozen.
Observation work adds no condition to the existing switch state machine.
If evidence is missing, stale, or unsupported, the observation reports
`failed`; the successful command remains successful. Startup, migration,
the initial Alpenglow epoch, and same-identity commands cannot establish
a supported distinct outgoing context. Full Alpenglow support requires
rooted evidence beyond the migration epoch, so it is conservative when
Replay or finality is behind. Sequence exhaustion also fails observation
without affecting the command.

On passive-to-active switching, the source is the passive identity:

```text
passive P (no outbound votes) -> request identity V
              |
       transitioning: from=P, to=V, submitted=null
              |
       existing switch finishes
              |
       complete: from=P, to=V, submitted=null
              |
       new votes under V do not change P's frozen observation
```

## Submission and safety limits

Under Tower, the counter advances after TxSend publishes the signed own
vote on its existing outbound transaction link. This includes a vote
accepted locally even if no direct leader endpoint was available. Under
Alpenglow, it advances after a successful own-vote datagram publication
on the existing network output. Failed datagram creation does not count.
Own broadcasts, standstill rebroadcasts, and reward retries count; received
votes and certificate broadcasts do not. Restored vote history and
generated but unsent votes do not seed or advance either counter. Slot zero
is distinct from `null`. Counters reset only when adopting a different
identity, independently of whether an observation can be published.

Submission does not establish transmission, peer acceptance, landing, or
finalization. Completion does not guarantee downstream queue drainage or
final vote-history persistence, and does not establish readiness to vote
under the destination identity. Use existing consensus state transfer and
lockout checks. A nullable watermark is not independent finality evidence.

Alpenglow vote slots are consensus-message evidence, not Tower vote-account
`lastVote` evidence. A consumer must use consensus-appropriate finality;
the observation does not add that policy or make an identity-only switch
safe by itself.

## Cost and tests

Each active submission updates two tile-local words. There are no new
locks, atomics, allocations, syscalls, files, threads, or messages per
vote. Tower also observes a feature flag during its existing bank query.
The shared observation snapshots are touched only during initialization,
transitions, and RPC queries. A dedicated public workspace prevents RPC readers from
mapping the admin workspace containing private key material; RPC joins
this workspace read-only.

Single-writer snapshots use atomic payload words and a generation check.
Readers make at most eight attempts and return unavailable instead of
waiting. The snapshot tests stress a concurrent reader/writer and cover
stale sequences, restarts, unsupported phases, slot zero, absence of votes,
and same-identity commands. Tile tests cover the actual Tower/TxSend/Votor
freeze boundaries, successful and failed datagram publication, certificate
exclusion, RPC serialization/parameters, and unchanged admin rejection.

`bench_identity_transition` measures synthetic local bookkeeping only.
It does not measure validator throughput, networking, or switch latency.

Example build and targeted checks (from the repository root):

```sh
make -j8 firedancer firedancer-dev test_identity_transition test_admin_tile \
  test_txsend_tile test_votor_tile test_tower_tile test_replay_tile test_rpc_tile \
  bench_identity_transition

identity_objdir=$(make --silent objdir)
"${identity_objdir}/unit-test/test_identity_transition"
"${identity_objdir}/unit-test/test_admin_tile"
"${identity_objdir}/unit-test/test_txsend_tile"
"${identity_objdir}/unit-test/test_votor_tile"
"${identity_objdir}/unit-test/test_tower_tile" --page-sz normal --page-cnt 1048576
"${identity_objdir}/unit-test/test_replay_tile" --page-sz normal --page-cnt 524288
"${identity_objdir}/unit-test/test_rpc_tile"
"${identity_objdir}/unit-test/bench_identity_transition"
```

Use the same `MACHINE`, `EXTRAS`, and other build settings for the build and
`make --silent objdir`. The ordinary page arguments above let the larger
fixture tests run without huge pages.
