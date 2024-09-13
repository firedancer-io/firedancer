# Introduction
We observe three problems with Proof of History,

 * It solves the problem of how to enforce a minimum block time with
   more complexity than is needed, leading to performance problems and
   implementation difficulties for both the TPU and TVU.  See Appenndix
   A.

 * The design allows, and economically encourages validators to deviate
   from 400ms block times, to the detriment of the cluster.  See
   Appendix B.

 * The cluster does not encourage or reward faster nodes and hardware
   upgrades, and individual nodes are economically incentivized to use
   cheaper hardware.

We suggest an evolved design which tries to address these shortcomings
below.  The component is renamed from "Proof of History" to the Slot
Time Prover, or STP, to represent the new role more clearly.

The design is conceptual and is being presented to generate discussion
and exploration of the solution space.  It is not, and is not intended
to be fully specified or implementable.

# Slot Time Prover
Recall that Solana has elegantly solved a key problem with PoH: how to
enforce a minimum block time in a distributed, deterministic way.
Roughly,

 1. Take the fastest hardware a reasonable validator might have
 2. Determine the number of hashes such hardware can do in ~400 milliseconds
 3. Require proof that this number of hashes was done serially on blocks

Keeping block times on target is then conceptually simple: keep this
hash count up to date, and the block time is bounded from below.  If we
can economically incentivize fast blocks from leaders, they will be
pressured from above also, and so produce blocks down near this time
floor.  As a bonus, the economic incentive will also serve to keep
validators upgrading their hardware, and force slower nodes off the
network naturally.

## Incentivizing Fast
Let `H` be the number of hashes in a slot, and a leader `A` be followed by
leader `B`, by leader `C`....  Assume leaders `A`, `B`, ... take `T(A)`,
`T(B)`, ... time to produce a single hash.

```
+---------------+---------------+---------------+
|       A       |       B       |       C       |
+---------------+---------------+---------------+
| 0 | 1 | 2 | 3 | 0 | 1 | 2 | 3 | 0 | 1 | 2 | 3 |
+---------------+---------------+---------------+
|      4*H      |
+---------------+---------------+
| 4*H*T(A)/T(B) |      4*H      |
+---------------+---------------+---------------+
| 4*H*T(A)/T(C) | 4*H*T(B)/T(C) |      4*H      |
+---------------+---------------+---------------+
                       ...
```

Now observe an interesting property: leader `C` can prove how fast their
hashing was *relative* to the speed of `A` and `B`.  In fact given a
leader `H`, we can compute,

```
 Total hashes = 4*H*(T(A) + T(B) + ... + T(G) + 1)
 Our hashes = 4*H
 Our share = 1 - (Our hashes / Total hashes) = 1 - 1/(T(A) + T(B) + ... + T(G) + 1)
```

It is evident that for equally fast leader nodes our share of time
should be around `1/8`.  If it's higher, we are a slow node, and if it's
lower we are a fast node.  From here it is simple to define a piecewise
function to assign the fees for the block to various leaders. One simple
function is given,

```
f(x) = 
    1                   for x <= 1/8
    (1 - 8 * (x - 1/8)) for 1/8 < x < 1/4
    0                   for x >= 1/4
```

The specific function and history window and reward assignments can be
tweaked to get the desired outcomes, but this is the basic scheme.
Reward nodes directly for being fast by giving them a share of slower
neighboring leaders' fees.

## Incentivizing Skipping
Now that we have encouraged nodes to produce blocks as quick as they
can, we need to encourage them to skip slow leaders.  Recall from the
game theory in Appendix B that rational nodes will not attempt to skip
to preserve leader optionality and avoid getting skipped themselves.

In practice there is one sure way to do this: allow equivocated slots.
If a leader can attempt to skip, lose the race, and then immediately
publish a replacement slot building on the other fork.

## Refactoring
The mixin operation is no longer needed to secure the chain and would be
removed, as it is slow and creates a bottleneck during transaction
execution.  The slot time prover would attach time proofs to the last
shred for our leader slots.  To preserve fast replay, multiple
intermediate proofs could be published so replay nodes can verify in
parallel.

An added benefit: the compute unit system put in place to try to fix
block sizes and times could eventually be removed, as there would be no
incentive to produce a large block.  The network will skip it, and if
they don't, the leader will get no fees for it due to taking too long to
produce.

# Appendix A. Utility of PoH.
The Solana whitepaper originally conceived that Proof of History would
prevent a variety of attacks, and this is behind the current design of
mixins.  In the current use, these attacks tend to be prevented by other
components:

 * Long range attacks are prevented by vote lockouts, the consensus and
   tower mechanics, and fast confirmation times.  PoH does not prevent
   these attacks, as an attacker could find fast dedicated hardware to
   catch up and surpass the cluster slot height.

 * Transactions are recorded and verified into the ledger via. the bank
   hash, and the Proof of History hash is not needed to secure the
   ledger.

 * The mixin operation does not generally prove ordering between
   transactions, a leader node is free to order transactions in their
   block arbitrarily.

# Appendix B. Game Theory of PoH.

Imagine an idealized Solana cluster with no network propagation delay,
and no slow or offline leaders, all validators are economically rational
and act according to their own incentive.  Further, assume a leader
schedule comprising three nodes, `A`, `B`, and `C` in sequence as
follows, and that time to produce enough hashes for one leader slot of
`A`, `B`, and `C` is given by `H(A)`, `H(B)`, and `H(C)`. 

```
+---------------+---------------+---------------+
|       A       |       B       |       C       |
+---------------+---------------+---------------+
| 0 | 1 | 2 | 3 | 0 | 1 | 2 | 3 | 0 | 1 | 2 | 3 |
+---------------+---------------+---------------+
```

If the cluster reaches slot `B0`, node `B` has a choice of what to do,
we look at their choices,
 
 * Do nothing.  There is no incentive to do this, the node wants to earn
   fees.

 * Publishing before `H(B)` is not possible.

 * Publish at `H(B)`.  No incentive to do this.  The node can collect
   higher fees from incoming transactions if it takes longer to publish.
   There is a minor incentive to publish quickly, as inflation rewards
   are accelerated, but this is not a significant payoff on the scale of
   a single slot, as compared to the fees.

Here it becomes interesting to consider fork choice.  In the idealized
cluster, if `C0` is built on `A3`, skipping `B0`, `C0` will win the fork
if it's published before `B0` and lose otherwise.  This is because all
validators will vote immediately, be locked out for two slots, and then
be prevented from switching fork because it is not heavier than their
selected fork.

 * Publish at 400 milliseconds.  No incentive to do this.  The node
   knows it cannot get skipped until `5*H(C)`, so as in case `H(B)`, it
   is better off to keep waiting.  This is also true for all publish
   timestamps between `H(B)` and `5*H(C)`.

 * Publish at (or a nanosecond before) `5*H(C)`.  Strong incentive.  No
   risk of getting skipped, more fees.

 * Publish after `5*H(C)`.  No incentive.  We assume Node C will skip us
   to take fees for pooled transactions (per the current
   implementation).

So given the current implementation, the incentive for node `B` is to
determine `H(C)` and publish at `5*H(C)`.

Let's now look at the behavior of node `C`.  What choices do they have
when confronted with such an economic agent in front of them?

  * Publishing before `5*H(C)` is not possible.

  * In fact, even starting a block at `4*H(C)` which skips `B` is a bad
    idea, sending shreds out will prevent C from becoming leader of `C0`
    again once `B0` is accepted (else it will equivocate).

  * So it's best for `C` to wait to `5*H(C)` to start producing `C0`.

Now see that if `C` waits til `5*H(C)` to start, they will publish at
`5*H(C) + k`, but inductively, leader B will now publish at
`5*H(C) + k`, and so the process repeats.  The equilibrium for nodes
today is then that node `B` takes infinitely long to publish, and node
`C` (and all future nodes behind it) wait indefinitely.

The situation is even worse: it might appear that node `C` can stop this
game by choosing to skip and publish, thereby collecting fees.  In
practice, publishing a slot takes some publishing time, `P(A)`, `P(B)`,
`P(C)`, which may run concurrently with hashing time, and which is
observable by all other nodes.  Leader `B` can publish parts of `B0` in
time to maintain the invariant that `P_remaining(B) < P_remaining(C)`,
thereby preventing itself ever getting skipped.

In a real network, it's likely that propogation and information delays
would eventually incentivize node `C` to make a risky attempt to skip, to
collect a juicy pool of transations, but not before a large delay.
