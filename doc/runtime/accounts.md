# Accounts

## Account Accesses

The following types of account accesses exist:

1. [External account reads](#external-account-reads)
2. [Transaction validity checks](#transaction-validity-checks)
3. [Transaction account accesses](#transaction-account-accesses)
4. [Program executions](#program-executions)
5. [Sysvar reads](#sysvar-reads)
6. [System accesses](#system-accesses)

### External account reads

Read-only users may observe any account at any time by interfacing with
the account database of a Solana node.  These *external account read*
accesses only reveal [*stored accounts*](#stored-accounts).

Typical methods for *external account reads* are the `getAccount()` or
`getProgramAccounts()` RPC methods, or the `update_account()` Geyser
callback.

The consensus component of a validator is another source of external
account reads.

### Transaction validity checks

Reads from [*stored accounts*](#stored-accounts) may be necessary to
determine whether a transaction is valid or not.  Specific types of
reads include
- fee payer check (any stored account)
- nonce check (special read interest in [*nonce accounts*](#nonce-accounts))
- ALT lookup (special read interest in [*ALTs*](#alts))

*Transaction validity checks* also deduct the *transaction fee* from the
first signer account of the transaction (the *fee payer*).

### Transaction account accesses

Every Solana transaction specifies one or more accounts to access.
A transaction can indirectly specify account accesses via [ALTs](#alts).

These accounts then become available for read and write to programs
invoked by a transaction.  During transaction execution, various access
checks on writes are performed.

Writes to certain types of accounts are categorically restricted
(marks the transaction invalid, fails the transaction, or partially
reverts the write after the transaction completes).  These include:
- [Transparent Accounts](#transparent-accounts)
- [System managed accounts](#system-managed-accounts)

### Program executions

A *program execution* is a type of account access that results from
transaction execution.  The *program account* to execute is specified
in the transaction.  This access type is distinct from a [*transaction
account access*](#transaction-account-accesses).

A *program account* is either a [*BPF program account*](#bpf-program-accounts)
or a [*native program*](#builtin-accounts).

### Sysvar reads

Certain accounts can be read at any time during runtime execution.  This
includes the slot transition, native programs, and syscall handlers.

These accounts are either [*slot sysvars*](#slot-sysvars) or
[*ephemeral sysvars*](#ephemeral-sysvars).

### System accesses

When executing a slot, the runtime alternates between transaction
execution and miscellaneous system processing.  The latter includes any
slot execution phase during which transactions are not executed.  These
steps perform various writes to [*stored accounts*](#stored-accounts).

System accesses are also responsible for maintaining a cryptographic
hash over the stored set of accounts.  (See [SIMD-0215](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0215-accounts-lattice-hash.md))

## Account Taxonomy

Firedancer defines the following taxonomy for Solana accounts.  This
taxonomy is defined by which properties are shared between different
types of accounts.

1. [Transparent accounts](#transparent-accounts)
    1. [Ephemeral sysvars](#ephemeral-sysvars)
2. [Stored accounts](#stored-accounts)
    1. [User writable accounts](#user-writable-accounts)
        1. [Basic accounts](#basic-accounts)
        2. [Nonce accounts](#nonce-accounts)
        3. [ALTs](#alts)
        4. [BPF program accounts](#bpf-program-accounts)
        5. [Vote accounts](#vote-accounts)
        6. [Fee collector accounts](#fee-collector-accounts)
        7. [Stake accounts](#stake-accounts)
        8. [Incinerator](#incinerator)
    2. [System managed accounts](#system-managed-accounts)
        1. [Slot sysvars](#slot-sysvars)
        2. [Builtin accounts](#builtin-accounts)

### Transparent Accounts

Transparent accounts are generated entirely from runtime execution
context such as the bank or the currently executed instruction.
Transparent accounts are not stored in the account database.

When read via a [*transaction account access*](#transaction-account-accesses)
or a [*sysvar read*](#sysvar-reads), the account is generated on-the-fly.
Transactions may not specify this account as writable in an access list.

[*External account reads*](#external-account-reads) observe a
non-existent account when trying to read *transparent accounts*.

[*System writes*](#system-writes) to transparent accounts are inherently
undefined, since the written data would not persist.

### Ephemeral Sysvars

Ephemeral sysvars are transparent accounts that are accessible through
*sysvar reads*.

For more information, see [sysvars.md](./sysvars.md#slot-sysvars)

### Stored Accounts

Accounts are *stored accounts* if they get read and written from/to the
account database.

All stored accounts are accessible via [*external account reads*](#external-account-reads)
and [*transaction account accesses*](#transaction-account-accesses).

### User writable accounts

User writable accounts can be modified via any [*transaction account access*](#transaction-account-accesses).

Most modifications are subject to permission checks.  Increasing the
lamport value of an account always passes the permission checks of a
*user writable account*.

[*System writes*](#system-writes) occasionally modify these accounts for
rent collection.

### Basic accounts

An account is a *basic account* if it does not fall under any other
subcategory of [*user writable account*](#user-writable-accounts).

### Nonce accounts

*Nonce accounts* are user writable stored accounts that have special
meaning during [*transaction validity checks*](#transaction-validity-checks).

*Transaction validity checks*, *transaction account accesses*, and
*system accesses* read and write nonce accounts.  Special contracts
between these components exist to relax data dependencies.

### ALTs

*ALTs* act as a dictionary compression scheme when specifying account
addresses in transactions.  Therefore, they have special meaning during
[*transaction validity checks*](#transaction-validity-checks).

In order to relax data dependencies between the *transaction validation*
and *transaction execution* phases of block execution, ALTs must first
be locked before they can be updated.

### BPF program accounts

There are two type of *BPF program accounts*: *User BPF programs* and
*Core BPF programs*.  Not to be confused with *native programs*, which
are a separate concept.

*User BPF programs* hold bytecode programs deployed by users and their
supporting metadata.

Before the runtime can [*execute a program*](#program-executions), it
must first derive executable bytecode by running the "ELF loader" and
"bytecode verifier" steps.  Because these steps are rather expensive,
the runtime facilitates transparent caching of executable bytecode.

This is done using logic in the BPF Loader native programs:
- The number of executable revisions of the same program is limited to
  one per slot.
- Program byte code is immutable while it is executable
  (i.e. potentially in the cache)
- Transitioning a program between immutable/executable, and
  mutable/non-executable incurs a one slot delay.

### Core BPF programs

*Core BPF programs* are similar to [user BPF programs](#user-bpf-programs)
but provide essential runtime facilities.  Typically, core BPF program
updates are only possible via feature gate activations (which perform
writes via [*system accesses*](#system-accesses)).

### Vote accounts

*Vote accounts* are essential to the Solana consensus layer.

Validators frequently dispatch writes via transactions to *vote
accounts* by invoking consensus-specific logic in the *vote program*,
see [*transaction account accesses*](#transaction-account-accesses).

The runtime periodically dispatches [*system accesses*](#system-accesses)
for *vote accounts* to convert *vote credits* into *stake rewards*.

Various other validator components simultaneously dispatch [*external account reads*](#external-account-reads).
These include consensus (voting, fork choice), and network components
(stake weighted QoS in repair and gossip).

### Fee collector accounts

A *fee collector account* gains *fee rewards* during runtime
[*system accesses*](#system-accesses).

Each slot, the *vote authority* of the leader *vote account* is
designated as the *fee collector*.

### Stake accounts

*Stake accounts* implement stake delegation to [*vote accounts*](#vote-accounts).
Stake accounts are infrequently accessed via [*transaction account
accesses*](#transaction-account-accesses).  Stake accounts are also
updated approximately once per epoch using [*system accesses*](#system-accesses)
to accrue *inflation rewards*.

### Incinerator

The *incinerator* has a hardcoded account address `1nc1nerator11111111111111111111111111111111`.

At the end of every slot, a [*system access*](#system-accesses) sets the
account's lamport balance to zero, and updates the bank's capitalization
accordingly.

### Slot sysvars

Readable for any access type.  Only [*system accesses*](#system-accesses)
can write sysvar data.

See [sysvars.md](./sysvars.md#slot-sysvars).

### Builtin accounts

Readable for any access type.  Only [*system accesses*](#system-accesses)
write sysvar data.

*Builtin accounts* are *stored accounts* that are usually just
placeholders.  For example, the data content of `Stake11111111111111111111111111111111111111`
(the stake program) is just `stake_program_v3` at the moment.

Some *builtin accounts* have special behavior when accessed via a
[*program execution*](#program-executions).  For example, the "system
program" invokes a hardcoded runtime instruction processor.  These
builtins are also called *native programs*.
