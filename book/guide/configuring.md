# Configuring

## Overview
Firedancer is configured via. a [TOML](https://toml.io/en/) file. Almost
all options have a recommended default value that is set automatically
by Firedancer, and an operator needs only to specify values for options
they wish to change. The full list of options is as specified in the
[`default.toml`](https://github.com/firedancer-io/firedancer/blob/main/src/app/fdctl/config/default.toml)
file is documented below.

::: tip MIGRATING

The Agave validator is configured with command line options like
`--identity identity.json --rpc-port 8899`. When migrating your scripts,
these command line options will need to move to the corresponding
configuration option in the TOML file.

:::

The full list of available options and their defaults are documented
below. An example TOML file overriding select options needed for a new
validator on testnet might look like:

::: code-group

```toml [testnet.toml]
user = "firedancer"

[gossip]
    entrypoints = [
        "entrypoint.testnet.solana.com:8001",
        "entrypoint2.testnet.solana.com:8001",
        "entrypoint3.testnet.solana.com:8001",
    ]

[consensus]
    expected_genesis_hash = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"
    known_validators = [
        "5D1fNXzvv5NjV1ysLjirC4WY92RNsVH18vjmcszZd8on", 
        "dDzy5SR3AXdYWVqbDEkVFdvSPCtS9ihF5kJkHCtXoFs",
        "Ft5fbkqNa76vnsjYNwjDZUXoTWpP7VYm3mtsaQckQADN",
        "eoKpUABi59aT4rR9HGS3LcMecfut9x7zJyodWWP43YQ",
        "9QxCLckBiJc783jnMvXZubK4wH86Eqqvashtrwvcsgkv",
    ]

[rpc]
    port = 9099
    full_api = true
    private = true

[consensus]
    identity_path = "/home/firedancer/validator-keypair.json"
    vote_account_path = "/home/firedancer/vote-keypair.json"
```

:::

Once your configuration file is created you can use it by either
setting the `FIREDANCER_CONFIG_TOML` environment variable, or by
passing it to your command with the `--config` option.

::: tip NOTE

The same configuration file must be supplied to all commands, especially
when configuring and later running the validator. Using a different file
for different commands may cause them to fail.

:::

## Logging
By default Firedancer will maintain two logs. One permanent log which is
written to a file, and an ephemeral log for fast visual inspection which
is written to stderr. The Agave runtime and consensus components also
output logs which are a part of the Firedancer's logs. You can increase
the ephemeral log output in the configuration TOML.

```toml
[log]
    level_stderr = "INFO"
```

## Layout
One way that Firedancer is fast is that it pins a dedicated thread to
each CPU core on the system. Each thread can do one specific kind of
work, for example, a `verify` tile can verify the signatures of incoming
transactions. Tiles are connected together in a graph to form an
efficient pipeline for processing transactions.

::: warning WARNING

Each tile needs a dedicated CPU core and it will be saturated at 100%
utilization. The Agave process will run on the cores under the
`agave_affinity` and this should not overlap with tile cores. 

:::

The configuration file has options for how many of each kind of tile
should be started.


```toml
[layout]
    affinity = "1-18"
    quic_tile_count = 2
    verify_tile_count = 4
    bank_tile_count = 4
    agave_affinity = "19-31"
```

It is suggested to run as many tiles as possible and tune the tile
counts for maximum system throughput so that the Solana network can run
faster.  There are some example tuned configurations in the
`src/app/fdctl/config/` folder to work from.

## Options
The list of all available configuration options and their default values
is provided below. You only need to override options which you wish to
change.

::: code-group

<<< @/../src/app/fdctl/config/default.toml

:::
