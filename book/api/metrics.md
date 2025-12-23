# Metrics

## Overview
Firedancer maintains many internal performance counters for use by
developers and monitoring tools, and exposes them via a
[Prometheus](https://prometheus.io/docs/introduction/overview/) HTTP
endpoint:

::: code-group

```toml [config.toml]
[tiles.metric]
    prometheus_listen_port = 7999
```

:::

```sh [bash]
$ curl http://localhost:7999/metrics
# HELP tile_pid The process ID of the tile.
# TYPE tile_pid gauge
tile_pid{kind="net",kind_id="0"} 1527373
tile_pid{kind="quic",kind_id="0"} 1527370
tile_pid{kind="quic",kind_id="1"} 1527371
tile_pid{kind="verify",kind_id="0"} 1527369
tile_pid{kind="verify",kind_id="1"} 1527374
tile_pid{kind="dedup",kind_id="0"} 1527365
...
```

::: warning WARNING

Metrics are currently only provided for developer and diagnostic use,
and the endpoint or data provided may break or change in incompatible
ways at any time.

:::

There are three metric types reported by Firedancer, following the
[Prometheus data model](https://prometheus.io/docs/concepts/metric_types/):

 - `counter` &mdash; A cumulative metric representing a monotonically increasing counter.
 - `gauge` &mdash; A single numerical value that can go arbitrarily up or down.
 - `histogram` &mdash; Samples observations like packet sizes and counts them in buckets.

<!--@include: ./metrics-generated.md-->
