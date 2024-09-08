Most performance counters are local to a tile and are not aggregated.
For example if you have two QUIC tiles (two CPU cores assigned to
serving incoming QUIC connections) each QUIC counter will appear twice:

```sh [bash]
# HELP quic_connections_created The total number of connections that have been created.
# TYPE quic_connections_created counter
quic_connections_created{kind="quic",kind_id="0"} 42145
quic_connections_created{kind="quic",kind_id="1"} 38268

# HELP quic_connections_aborted Number of connections aborted.
# TYPE quic_connections_aborted counter
quic_connections_aborted{kind="quic",kind_id="0"} 14
quic_connections_aborted{kind="quic",kind_id="1"} 23
```

All tile related metrics have just two labels, and these are to
identify which tile (and which tile index, for tiles of the same kind)
the metric is for:

- `kind` &mdash; The tile name the metric is being reported for.
- `kind_id` &mdash; The tile index of the tile which is reporting the
metric.
