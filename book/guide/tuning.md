# Performance Tuning

## Overview
The Firedancer validator is composed of a handful of threads, each
performing a distinct job. Some jobs only need one thread to do them,
but certain jobs require many threads performing the same work in
parallel.

Each thread is given a CPU core to run on, and threads take ownership of
the core: never sleeping or letting the operating system use it for
another purpose. The combination of a job, and the thread it runs on,
and the CPU core it is assigned to is called a tile. The fifteen kinds of
tile are,

| Tile   | Description |
|--------|-------------|
| `net`  | Sends and receives network packets from the network device |
| `quic` | Receives transactions from clients |
| `verify` | Verifies cryptographic signatures on incoming transactions, filtering invalid ones |
| `dedup` | Checks for and filters out duplicated incoming transactions |
| `resolv` | Resolves address lookup tables (ALTs) before transactions are scheduled |
| `pack` | Collects incoming transactions and schedules them for execution when we are leader |
| `execle` | Executes transactions that have been scheduled during leader slots |
| `poh`  | Continuously hashes in the background, mixing in executed transactions to prove passage of time |
| `shred` | Distributes block data to the network when leader, and receives and retransmits block data when not leader |
| `replay` | Manages forks and schedules transactions when replaying blocks produced by other nodes |
| `execrp` | Executes transactions when replaying blocks produced by other nodes |
| `accdb` | Runs account database background work such as writing cached accounts back to disk |
| `tower` | Implements Tower BFT consensus and manages voting |
| `gossip` | Runs the gossip protocol for discovering peers |
| `gossvf` | Verifies cryptographic signatures on incoming gossip messages |
| `repair` | Requests and reconstructs missing blocks from peers via the repair protocol |
| `rserve` | Serves block data to other peers via the repair protocol |
| `txsend` | Transmits outbound transactions (such as votes or forwarded transactions) to leaders |
| `sign` | Holds the validator private key, and receives and responds to signing requests from other tiles |
| `gui` | Serves the web dashboard and WebSocket streaming API |
| `metric` | Collects monitoring information about other tiles and serves it on an HTTP endpoint |
| `diag` | Counts context switches and diagnostic information of other tiles |
| `netlnk` | Synchronizes Linux network configuration |

These tiles communicate with each other via shared memory queues. The
work each tile performs and how they communicate with each other is
fixed, but the count of each tile kind and which CPU cores they are
assigned to is set by your configuration, and this is the primary way to
tune the performance of Firedancer.

## Configuration
The default configuration provided if no options are specified is given
in the [`default.toml`](https://github.com/firedancer-io/firedancer/blob/main/src/app/firedancer/config/default.toml)
file:

::: code-group

```toml [default.toml]
[layout]
    affinity = "auto"
    net_tile_count = 2
    quic_tile_count = 1
    verify_tile_count = 6
    resolv_tile_count = 1
    gossvf_tile_count = 2
    execle_tile_count = 2
    execrp_tile_count = 10
    shred_tile_count = 1
    sign_tile_count = 2
```

:::

Tile counts for `net`, `quic`, `verify`, `resolv`, `gossvf`, `execle`,
`execrp`, `shred`, and `sign` are configurable. Optional tiles like
`gui` and `rpc` can also be enabled or disabled. Other tiles run as
single instances.

The assignment of tiles to CPU cores is determined by the `affinity`
string, which is documented fully in the
[`default.toml`](https://github.com/firedancer-io/firedancer/blob/main/src/app/firedancer/config/default.toml)
file itself.

The following table shows the performance characteristics of the
adjustable tiles, along with recommendations for `mainnet`:

| Tile     | Default         | Notes |
|----------|-----------------|-------|
| `net`    | 1               | Handles >1M TPS per tile. Designed to scale out for future network conditions, but there is no need to run more than 1 net tile at the moment on `mainnet-beta` |
| `quic`   | 1               | Handles >1M TPS per tile. Designed to scale out for future network conditions, but there is no need to run more than 1 QUIC tile at the moment on `mainnet-beta` |
| `verify` | 4               | Handles 20-40k TPS per tile. Recommend running many verify tiles, as signature verification is the primary bottleneck of the application |
| `execle` | 4               | Handles 20-40k TPS per tile, with diminishing returns from adding more tiles. Designed to scale out for future network conditions, but 4 tiles is enough to handle current `mainnet-beta` conditions. Can be increased further when benchmarking to test future network performance |
| `shred`  | 1               | Throughput is mainly dependent on cluster size, 1 tile is enough to handle current `mainnet-beta` conditions. In benchmarking, if the cluster size is small, 1 tile can handle >1M TPS |

## Testing
Firedancer includes a simple benchmarking tool for measuring the
transaction throughput of the validator when it is leader, in
transactions per second (TPS). In practice, the Solana network
performance is limited by two factors that are unrelated to what
this tool measures:

 - The replay performance of the slowest nodes in the network, and if
they can keep up
 - The consensus limits on block size and data size

In particular, consensus limits on the Solana protocol limit the network
strictly to around 81,000 TPS. But the tool can be useful for testing
local affinity and layout configurations.

The benchmark runs on a single machine and performs the following:

 1. A new genesis is created, and set of accounts are pre-funded
 2. A set of CPU cores is assigned to generating and signing simple
transactions using these accounts as fast as possible
 3. Another set of CPU cores is assigned to sending these transfers
via QUIC over loopback to the locally running validator
 4. Around once a second, an RPC call is made to get the total count of
transactions that have executed on the chain, and this information is
printed to the console

The benchmark is currently quite synthetic, as it only measures single
node performance, in an idealized case where all transactions are
non-conflicting.

## Running
The benchmark command is part of the `firedancer-dev` development binary,
which can be built with `make -j firedancer-dev`. With the binary built,
we can run our benchmark (here on a 32 physical core AMD EPYC 7513):

```sh [bash]
$ lscpu
Architecture:        x86_64
CPU(s):              64
On-line CPU(s) list: 0-63
Thread(s) per core:  2
Core(s) per socket:  32
Socket(s):           1
NUMA node(s):        1
Vendor ID:           AuthenticAMD
Model name:          AMD EPYC 7513 32-Core Processor
```

```sh [bash]
$ ./build/firedancer-dev bench
```

<<< @/snippets/bench/bench1.ansi

We have not provided a configuration file to the bench command, so it
is using the stock configuration from `default.toml` and reaching around
63,000 TPS.

Let's take a look at the performance with the `monitor` command and see
if we can figure out what's going on.

<<< @/snippets/bench/bench2.ansi

If we narrow in on just the verify tiles we can see the problem: all of
the verify tiles are completely busy processing incoming transactions,
and so additional transactions are being dropped. Here `% finish`
indicates the percentage of time the tile is occupied doing work, while
`overnp cnt` indicates that the tile is being overrun by the quic tile
and dropping transactions.

<<< @/snippets/bench/bench3.ansi

This configuration is not ideal. With some tuning to increase the number
of verify tiles, and a few other changes we can try to achieve a higher
TPS rate,

::: code-group

```toml [bench-zen3-32core.toml]
[layout]
  # Dedicate more tiles to signature verification and leader execution
  net_tile_count = 1
  quic_tile_count = 1
  resolv_tile_count = 1
  verify_tile_count = 31
  gossvf_tile_count = 1
  execle_tile_count = 3
  execrp_tile_count = 1
  shred_tile_count = 1
  sign_tile_count = 2

[development.genesis]
  # Pre-fund more accounts so more transfers can be handled in parallel
  fund_initial_accounts = 32768

[development.bench]
  # Use more generator and sender tiles to saturate the validator
  benchg_tile_count = 12
  benchs_tile_count = 2

  # Raise protocol consensus limits for testing
  max_cost_per_block = 540000000
  max_shreds_per_block = 131072

[tiles.shred]
  max_pending_shred_sets = 16384

[tiles.pack]
  schedule_strategy = "perf"
```

:::

Now run the benchmark with the tuned configuration:

```sh [bash]
$ ./build/firedancer-dev bench --config src/app/firedancer/config/bench-zen3-32core.toml
```

<<< @/snippets/bench/bench7.ansi

## CPU isolation
Because tiles take permanent ownership of their CPU cores, anything
else the kernel runs on those cores — other processes, deferred kernel
work, interrupt handlers, or the periodic scheduler tick — directly
steals time from the validator and adds latency jitter. Several
[configure stages](/guide/initializing.md) reduce this interference and
are recommended for production deployments:

 * **irq-affinity** and **irq-balance** steer device interrupts away
from tile CPUs.
 * **kworkers** steers deferred kernel work (writeback, filesystem
maintenance) away from tile CPUs.
 * **cpuset** places tile CPUs in an isolated or root cgroup partition
 so no other process can be scheduled onto them at all.
 * **console** quiets periodic kernel console rendering (cursor blink,
warning-level message drawing), which runs on the CPU that generated
it and so cannot be steered away by the stages above.

Additionally, two kernel boot parameters remove the last sources of
interruption. These cannot be set at runtime, and Firedancer will
suggest them with the correct CPU list for your configuration when it
starts:

 * `nohz_full=<tile cpus>` stops the periodic scheduler tick (typically
250 interruptions per second per core) on CPUs running a single task.
 * `rcu_nocbs=<tile cpus>` moves RCU callback processing onto
housekeeping cores.

The effect of interference on each tile is observable in the
[monitoring](/guide/monitoring.md) output: context switches, interrupt
counts, and the time stolen by interrupt handlers are reported per
tile.
