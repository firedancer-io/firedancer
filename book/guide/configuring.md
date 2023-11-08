# Configuring

## Configuration file
Firedancer is configured via. a [TOML](https://toml.io/en/) file. Almost
all options have a recommended default value that is set automatically
by Firedancer and an operator needs only to specify values for options
they wish to change. It is not recommended to edit the `default.toml`
file directly as it is compiled into the binary.

::: tip MIGRATING

The Solana labs validator is configured with command line options like
`--identity identity.json --rpc-port 8899`. When migrating your scripts,
these command line options will need to move to the corresponding
configuration option in the TOML file.

:::

You can see all of the available options and their defaults by looking
at the [default.toml](https://github.com/firedancer-io/firedancer/blob/main/src/app/fdctl/config/default.toml)
file. An example TOML file overriding select options needed for a new
validator might look like:

```sh [bash]
# /home/firedancer/config.toml
user = "firedancer"
[gossip]
    entrypoints = [
      "10.0.0.2:8001"
    ]
[rpc]
    port = 9099
[consensus]
    identity_path = "/home/firedancer/validator-keypair.json"
    vote_account_path = "/home/firedancer/vote-keypair.json"
```

Once your configuration file is specified you can use it by either
setting the `FIREDANCER_CONFIG_TOML` environment variable, or by
passing it to your command with the `--config` option.

::: tip NOTE

The same configuration file must be supplied to all commands, especially
when configuring and later running the validator. Using a different file
for different commands may cause them to fail.

:::

## Logging

## Layout
One way that Firedancer is fast is that it pins a dedicated thread to
each CPU core on the system. Each thread can do one specific kind of
work, for example, a `verify` tile can verify the signatures of incoming
transactions. Tiles are connected together in a graph to form an
efficient pipeline for processing transactions.

::: warning WARNING

Each tile needs a dedicated CPU core and it will be saturated at 100%
utlilization The Solana Labs process will run on the remaining cores,
and you must leave at least a few cores unpinned so that it is not
starved.

:::

The configuration file has options for how many of each kind of tile
should be started.


```toml
[layout]
    affinity = "0-14"
    net_tile_count = 4
    verify_tile_count = 4
    bank_tile_count = 4
```

By default Firedancer has set the count of each tile so that the system
can handle transactions from a 25GiB NIC at line rate. Except for the
warning noted above, it is suggested to run as many tiles as possible
so that the Solana network can run faster.

The `affinity` string in the `layout` section specifies which cores the
tiles will get assigned to. `bank` and `store` tiles are currently
managed by Solana Labs and will not get a pinned core.

## Ledger
By default, Firedancer stores the ledger in a scratch directory, defined
in the `ledger` section in the configuration TOML. The default path is
defined as `/home/{user}/.firedancer/{name}/ledger` where `name` and
`user` gets replaced by what is in the configuration file. Assuming you
have `name = fd1` (which is the default) and `user = firedancer` in the TOML
file, this resolves to `/home/firedancer/.firedancer/fd1/ledger`. You
can specify a custom path for the ledger by setting `ledger.path`:

```toml
[ledger]
    path = "/data/ledger"
```
