# Glossary

Overview of Solana/Firedancer-specific terminology.

## Account

A record in the account database. Consists of an account address, SOL
balance, program owner, and binary data.

Accounts have multiple revisions.

## Alpenglow

A major upgrade to the Solana consensus protocol developed by Anza.

## Bank

Commonly: A fork graph node corresponding to a Solana block.

A bank object also holds various state required to execute transactions
that is not present in the accounts database.

## Bundle

A sequence of transactions packed atomically without reordering or
interleaving other transactions.

Bundle transactions pay regular Solana fees, with "tips" as an
additional incentive for block producers.

Typically delivered via Jito gRPC protocol via the bundle tile.

## Chained Merkle Root (CMR)

Uniquely identifies a FEC set and the fork it is on.

## Cluster

Synonym for 'Solana network'. E.g. "mainnet-beta cluster".

## Consensus

An algorithm all Solana validators in the network run to gain a
consistent view of the state of the blockchain (i.e. which fork is
canonical and which blocks are finalized).

## Duplicate Confirmed

Tower BFT specific. A block is "duplicate confirmed" if 52% of stake
weight has voted for it.

Distinct from optimistic confirmation.

## Entry

Highly ambiguous, usually synonym of "microblock".

## Equivocation

Act of producing two or more conflicting/duplicate blocks at the same
slot, produced by the same leader.

## Feature

Short for "feature gate", a mechanism used to atomically activate
breaking changes or a new feature on a cluster. Typically requires code
changes in a validator.

## FEC set

Authenticated slice of a block. Multiple FEC sets produce one or more
microblocks.

## Fork

Sequence of blocks (path in a tree). A fork is uniquely identified by
either the block hash, bank hash, or chained merkle root of a slot.

## Fork Choice

Algorithm that picks a preferred fork/block given a list of forks and
various consensus information (e.g. votes, equivocation proofs).

## Gossip

Protocol validators use to propagate cluster state information (such as
contact info, votes, and epoch slots) to each other.

## Leader

Each Solana network has one leader (a validator) at any given time.
The leader changes periodically (every ~1.6 seconds as of May 2026).

## Repair

Protocol used to request block data from other validators.

## Root / rooting

Synonym of finalization. When a block is rooted, consensus guarantees
that this block, its transactions, and state changes are accepted
globally and will not be reverted.

## RPC

Shorthand for "Solana JSON-RPC", a protocol used to read data and submit
transactions.

## Snapshot

A file containing a copy of all accounts and bank state as of some
rooted slot.

## Solfuzz

Application that generates diverse random data (e.g. transactions) with
the goal of finding differences in behavior between Firedancer and other
validator implementations (e.g. Agave).

## Tile

Firedancer operating system thread running a message-passing event loop.

Tiles are usually pinned to CPU cores.

## Tower BFT

Original Solana consensus algorithm. Active on mainnet as of May 2026.

## Transaction

Usually refers to a Solana transaction, not a database transaction.

## Turbine

Protocol used to proactively push block data to other validators.

## Validator

Software that replicates all Solana transactions and executes them.
Optionally participates in voting and block production.

## XDP

Linux kernel API for fast networking.
