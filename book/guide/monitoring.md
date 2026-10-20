# Monitoring

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
Firedancer ships with a monitoring tool, which you can run on the same
host as the running validator to view tile and other performance
information.

```sh [bash]
$ firedancer monitor --config ~/config.toml
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
