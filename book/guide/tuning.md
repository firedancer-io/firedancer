# Tuning

## Tiles

To stay caught up with the cluster, the replay stage needs enough
cores and processing power. If you see your validator falling
behind with the default configuration, consider trying out the
following:

### Increase Shred Tiles

Example Original Config:

```toml
[layout]
    affinity = "1-18"
    quic_tile_count = 2
    verify_tile_count = 4
    bank_tile_count = 4
    solana_labs_affinity = "19-31"
```

Example New Config:

```toml
[layout]
    affinity = "1-18"
    quic_tile_count = 2
    verify_tile_count = 5
    bank_tile_count = 2
    shred_tile_count = 2
    solana_labs_affinity = "19-31"
```

This takes a core from the `bank` tile (transaction execution) and
gives it to another `shred` tile (turbine and shred processing). It
takes another core from another `bank` tile and gives it to a `verify`
(signature verification) tile.

### Increase Cores for Solana Labs

Example Original Config:

```toml
[layout]
    affinity = "1-18"
    quic_tile_count = 2
    verify_tile_count = 5
    bank_tile_count = 2
    shred_tile_count = 2
    solana_labs_affinity = "19-31"
```

Example New Config:

```toml
[layout]
    affinity = "1-16"
    quic_tile_count = 1
    verify_tile_count = 4
    bank_tile_count = 2
    shred_tile_count = 2
    solana_labs_affinity = "17-31"
```

This takes 1 core from the `quic` tile and another from the `verify`
tile gives them both to the solana labs threads (where the replay stage
runs).

## QUIC

There is a lot of QUIC traffic in the cluster. If the validator is
having a hard time establishing QUIC connections, it might end up
getting less transactions. Some parameters that can be tuned to address
this are (these 2 parameters need to be the same value):

```toml
[tiles.quic]
    max_concurrent_connections = 2048
    max_concurrent_handshakes  = 2048
```
