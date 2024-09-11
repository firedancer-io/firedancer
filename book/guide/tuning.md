# Performance Tuning

## Overview
The Firedancer validator is composed of a handful of threads, each
performing one of eleven distinct jobs. Some jobs only need one thread
to do them, but certain jobs require many threads performing the same
work in parallel.

Each thread is given a CPU core to run on, and threads take ownership of
the core: never sleeping or letting the operating system use it for
another purpose. The combination of a job, and the thread it runs on,
and the CPU core it is assigned to is called a tile. The eleven kinds of
tile are,

| Tile   | Description |
|--------|-------------|
| `net`  | Sends and receives network packets from the network device |
| `quic` | Receives transactions from clients, performing all connection management and packet processing to manage and implement the QUIC protocol |
| `verify` | Verifies the cryptographic signature of incoming transactions, filtering invalid ones |
| `dedup` | Checks for and filters out duplicated incoming transactions |
| `pack` | Collects incoming transactions and smartly schedules them for execution when we are leader |
| `bank` | Executes transactions that have been scheduled when we are leader |
| `poh`  | Continuously hashes in the background, and mixes the hash in with executed transactions to prove passage of time |
| `shred` | Distributes block data to the network when leader, and receives and retransmits block data when not leader |
| `store` | Receives block data when we are leader, or from other nodes when they are leader, and stores it locally in a database on disk |
| `metric` | Collects monitoring information about other tiles and serves it on a HTTP endpoint |
| `sign` | Holds the validator private key, and receives and responds to signing requests from other tiles |

These tiles communicate with each other via shared memory queues. The
work each tile performs and how they communicate with each other is
fixed, but the count of each tile kind and which CPU cores they are
assigned to is set by your configuration, and this the primary way to
tune the performance of Firedancer.

## Configuration
The default configuration provided if no options are specified is given
in the [`default.toml`](https://github.com/firedancer-io/firedancer/blob/main/src/app/fdctl/config/default.toml)
file:

::: code-group

```toml [default.toml]
[layout]
    affinity = "1-16"
    solana_labs_affinity = "17-31"
    net_tile_count = 1
    quic_tile_count = 1
    verify_tile_count = 4
    bank_tile_count = 2
    shred_tile_count = 2
```

:::

Note that not all tiles have a configurable count. The `dedup`, `pack`,
`poh`, `store`, `metric`, and `sign` tiles are fixed at one thread each.

The assignment of tiles to CPU cores is determined by the `affinity`
string, which is documented fully in the
[`default.toml`](https://github.com/firedancer-io/firedancer/blob/main/src/app/fdctl/config/default.toml)
file itself. The Frankendancer validator currently starts an Agave
process to perform functionality like replay, gossip, and repair that is
not yet implemented in Firedancer. The `solana_labs_affinity` string
determines the CPU cores that are given to the threads of this Agave
process.

The following table shows the performance of the adjustable tiles on an
Intel Icelake core, along with some performance notes and
recommendations for `mainnet-beta`,

| Tile     | Default         | Notes |
|----------|-----------------|-------|
| `net`    | 1               | Handles >1M TPS per tile. Designed to scale out for future network conditions, but there is no need to run more than 1 net tile at the moment on `mainnet-beta` |
| `quic`   | 1               | Handles >1M TPS per tile. Designed to scale out for future network conditions, but there is no need to run more than 1 QUIC tile at the moment on `mainnet-beta` |
| `verify` | 4               | Handles 20-40k TPS per tile. Recommend running many verify tiles, as signature verification is the primary bottleneck of the application |
| `bank`   | 2               | Handles 20-40k TPS per tile, with diminishing returns from adding more tiles. Designed to scale out for future network conditions, but 2 tiles is enough to handle current `mainnet-beta` conditions. Can be increased further when benchmarking to test future network performance |
| `shred`  | 2               | Throughput is mainly dependent on cluster size, 2 tiles is enough to handle current `mainnet-beta` conditions. In benchmarking, if the cluster size is small, 1 tile can handle >1M TPS |

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
via. QUIC over loopback to the locally running validator
 4. Around once a second, an RPC call is made to get the total count of
transactions that have executed on the chain, and this information is
printed to the console

The benchmark is currently quite synthetic, as it only measures single
node performance, in an idealized case where all transactions are
non-conflicting.

## Running
The benchmark command is part of the `fddev` development binary, which
can be built with `make -j fddev`. With the binary in hand, we can run
our benchmark, here it will be on a 32 physical core AMD EPYC 7513:

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
[ledger]
  # Place the ledger in memory rather than on disk so that writing the
  # ledger is not a performance bottleneck
  path = "/data/shm/{name}/ledger"

[layout]
  # We will need a lot of verify tiles, and a few more bank tiles to be
  # able to execute at higher TPS rates. Increase their core counts, and
  # assign the tiles to cores. We only need 1 shred tile, since there is
  # only 1 node in the cluster it can handle a high TPS rate by itself
  affinity = "14-57,f1"
  solana_labs_affinity = "58-63"
  verify_tile_count = 30
  bank_tile_count = 6
  shred_tile_count = 1

[development.genesis]
  # The default amount of accounts to use for the benchmark is 1024, but
  # to reach higher transaction throughput we need more accounts so that
  # more transfers can be handled in parallel
  fund_initial_accounts = 32768

[development.bench]
  # benchg tiles are used to generate and sign transactions in the
  # benchmarking tool, we are going to need more of them to test higher
  # TPS rate
  benchg_tile_count = 12

  # benchs tiles are for sending the transactions to Firedancer over
  # loopback, and we will need an extra one of these as well
  benchs_tile_count = 2

  # Assign these benchg, benchs (and the bencho tile which orchestrates
  # the benchmarking) to some CPU cores. The bencho assignment is
  # floating as it is not performance sensitive
  affinity = "f1,0-13"

  # The Solana protocol consensus limits restrict the benchmark to
  # around 81,000 TPS. We have special options to increase these limits
  # for testing and benchmarking
  larger_max_cost_per_block = true
  larger_shred_limits_per_block = true

[rpc]
  # Tracking certain transaction history and metadata to serve RPC
  # requests is expensive and can slow down our validator, turn this
  # functionality off
  transaction_history = false
  extended_tx_metadata_storage = false
```

:::

Now try running again,

<<< @/snippets/bench/bench4.ansi

We start out with a higher TPS rate but it quickly falls back to around
90k TPS. We can try to figure out why by running the `monitor` command.

<<< @/snippets/bench/bench5.ansi

The culprit is visible in the output, which will be clearer if we filter
it down to the relevant information,

<<< @/snippets/bench/bench6.ansi

Here we see what is happening. The blockstore is completely busy
spending 99.973% of its time storing data, while the PoH and shred tiles
are in back-pressure waiting for the the blockstore to catch up. The
blockstore is an Agave component built on RocksDB that is not rewritten
as part of Frankendancer.

::: code-group

```toml [bench-zen3-32core.toml]
[development.bench]
  disable_blockstore_from_slot = 1 // [!code ++]
```

:::

We can disable the blockstore specifically for benchmarking, to show the
performance of just the Firedancer components in the leader pipeline.
Now we can run one more time and see a reasonably good value for the TPS
throughput of Firedancer on this machine.

<<< @/snippets/bench/bench7.ansi
