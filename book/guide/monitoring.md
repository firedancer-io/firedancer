# Monitoring

## Agave CLI
Because Frankendancer runs the Agave validator, it can be monitored with
the standard Agave command line tools. First make sure you have built
the `solana` CLI binary:

```sh [bash]
$ make solana
    Finished release-with-debug [optimized + debuginfo] target(s) in 0.44s
```

Similar to `fdctl`, the compiled binary will be placed in
`./build/native/gcc/bin` by default.

::: tip NOTE

Many commands require RPC to be enabled on the validator, see the
[configuring](./configuring) guide for more information.

:::

**gossip:** check if the validator has joined gossip

```sh [bash]
$ solana -ut gossip
IP Address      | Identity                                     | Gossip | TPU   | RPC Address           | Version    | Feature Set
----------------+----------------------------------------------+--------+-------+-----------------------+------------+----------------
74.118.136.198  | 2CY8VXH2jummjSmwcusSj2jGMiaHE4eo7WQ9LScxykvt | 8001   | 9001  | 74.118.136.198:8899   | 0.106.11814| 4215500110
```

**catchup:** check if the validator is caught up

```sh [bash]
$ solana -ut catchup --our-localhost
⠤ 1 slot(s) behind (us:123 them:124)
```

**validators:** ensure the validator is voting

```sh [bash]
$ solana -ut validators
   Identity                                      Vote Account                            Commission  Last Vote        Root Slot     Skip Rate  Credits  Version            Active Stake
2CY8VXH2jummjSmwcusSj2jGMiaHE4eo7WQ9LScxykvt  uhiGpdNqcqPGzYuRfVxjiHQWKKJPwKRSaPiXXxwSy9K   100%  279227304 ( -1)  279227273 ( -1)   0.00%    54287  0.106.11814     70100.022292880 SOL (0.03%)
```

**block-production:** ensure the validator is producing blocks

```sh [bash]
$ solana -ut block-production
  Identity                                         Leader Slots  Blocks Produced    Skipped Slots        Skip Rate
  2CY8VXH2jummjSmwcusSj2jGMiaHE4eo7WQ9LScxykvt               16               16                0            0.00%
```

::: tip NOTE

You can also use the `agave-validator --ledger <PATH> monitor`
command with Frankendancer. For that, you need to build the
`agave-validator` binary from the `agave` repository.

:::

## Metrics
Firedancer exposes a large set of prometheus compatible metrics at a
HTTP endpoint, by default on port `7999` but this is configurable in
the TOML file.

```sh [bash]
$ curl http://localhost:7999/metrics
# HELP tile_pid The process ID of the tile.
# TYPE tile_pid gauge
tile_pid{kind="net",kind_id="0"} 1108973
tile_pid{kind="quic",kind_id="0"} 1108975
tile_pid{kind="verify",kind_id="0"} 1108978
```

See the [metrics API documentation](/api/metrics.html) for more
information on the available data.

## Live monitoring
Firedancer ships with a monitoring tool included in `fdctl`, which you
can run on the same host as the running validator to view tile and other
performance information.

```sh [bash]
$ fdctl monitor --config ~/config.toml
snapshot for 2024-06-25 17:32:25.795577630 GMT+00
    tile |     pid |      stale | heart |        sig | in backp |           backp cnt |  % hkeep |  % backp |   % wait |  % ovrnp |  % ovrnr |  % filt1 |  % filt2 | % finish
---------+---------+------------+-------+------------+----------+---------------------+----------+----------+----------+----------+----------+----------+----------+----------
     net | 1108973 |          - |     - |  run( run) |   -(  -) |          0(     +0) |   40.118 |    0.000 |   59.882 |    0.000 |    0.000 |    0.000 |    0.000 |    0.000
    quic | 1108975 |          - |     - |  run( run) |   -(  -) |          0(     +0) |    0.325 |    0.000 |   99.675 |    0.000 |    0.000 |    0.000 |    0.000 |    0.000
  verify | 1108978 |          - |     - |  run( run) |   -(  -) |          0(     +0) |    0.496 |    0.000 |   99.504 |    0.000 |    0.000 |    0.000 |    0.000 |    0.000
[...]
```

You can also view the Firedancer GUI in a browser. Refer to the
[configuration section](/guide/configuring.md#gui) to enable it.
