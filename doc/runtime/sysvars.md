# Sysvars

This page documents Firedancer's internal handling of Solana sysvars.

Sysvars are special accounts that are implicitly read and written by the
runtime.  Any program execution can read a sysvar, even when that sysvar
account was not referenced in that transaction's account list.

Any sysvars and sysvar categories specified in this document are valid
as of June 2025.  This document might be outdated for sysvars added
later.

## Caching

The Agave runtime maintains a "sysvar cache".  This cache holds data
structures deserialized from the 'data' field of sysvar accounts.

It is assumed that transactions / programs cannot directly change sysvar
data.  Sysvar data is only changed when transitioning between program
executions, transactions, or slots.

The design of this cache is dictated by the cache invalidation policy.
The invalidation policy, in turn, is dictated by the possible places
where the sysvar can update.

As of now (June 2025), sysvars can be categorized like so:

- **Ephemeral Sysvars**: Updated within a transaction (outside program execution)
- **Slot Sysvars**: Updated at the start or end of a slot (outside transaction execution)

Please note that "sysvar categories" are a Firedancer-specific concept
and are not defined in the SVM specification.

## Slot sysvars

The following sysvars are written outside of transaction execution, and
can only be read during transaction execution.  These can be cached
trivially:

| Name                 | Account                                       |
|----------------------|-----------------------------------------------|
| `clock`              | `SysvarC1ock11111111111111111111111111111111` |
| `epoch_schedule`     | `SysvarEpochSchedu1e111111111111111111111111` |
| `fees`               | `SysvarFees111111111111111111111111111111111` |
| `recent_blockhashes` | `SysvarRecentB1ockHashes11111111111111111111` |
| `rent`               | `SysvarRent111111111111111111111111111111111` |
| `slot_hashes`        | `SysvarS1otHashes111111111111111111111111111` |
| `slot_history`       | `SysvarS1otHistory11111111111111111111111111` |
| `stake_history`      | `SysvarStakeHistory1111111111111111111111111` |
| `epoch_rewards`      | `SysvarEpochRewards1111111111111111111111111` |
| `last_restart_slot`  | `SysvarLastRestartS1ot1111111111111111111111` |

Firedancer uses a **write-through** cache policy for these sysvars.

All writes to the above sysvars use the `fd_slot_sysvar_write` API, which:
- Writes bank fields corresponding to this sysvar
- Writes to account database

## Transaction sysvars

The following sysvars are generated from runtime context on read:

| Name           | Account                                       |
|----------------|-----------------------------------------------|
| `instructions` | `Sysvar1nstructions1111111111111111111111111` |

Firedancer uses a complex cache policy for these sysvars.
- Primarily backed by short-lived buffers, unique for each transaction
- Account writes via user transactions are banned
  (FIXME clarify what happens when this is attempted)
- Never written to the account database
- Account reads via user transactions are redirected to a custom
  callback (does not access the account database)

## Unresolved issues

**Lamport changes**

Unclear if lamport updates have consequences for the sysvar cache (which
only caches data, but not metadata).

Particularly interesting for `Sysvar1nstructions1111111111111111111111111`.

**Crafted snapshot attack**

A Solana snapshot might be hacked to contain invalid sysvar data (that
fails bincode decoding).  It is unclear how the Agave runtime handles
accesses for those invalid sysvars.

Unclear what happens if TxnSysvar accounts are restored from snapshots.
