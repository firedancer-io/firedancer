# Monitoring

The Frankendancer validator can be monitored quite similar to an
Agave validator.

## Pre-requisite

Be sure to build the `solana` binary, i.e. specify `solana` as a
target to the `make` command. The binary should be in the same
directory as `fdctl`. If you have not added that directory to the
`PATH` environment variable, replace `solana` with the full path
to the binary in the following commands.

::: tip NOTE

Note that this list is not exhaustive. Some commands may not
work without RPC enabled on your validator. Check out the
comments in the `rpc` section of the `default.toml` file to
configure it according to your needs.

:::

## Solana Commands

* Ensure the validator has joined gossip

```sh [bash]
solana -ut gossip | grep <PUBKEY>
```

* Ensure the validator is caught up

```sh [bash]
solana -ut catchup --our-localhost
```

* Ensure the validator is voting

```sh [bash]
solana -ut validators | grep <PUBKEY>
```

* Ensure the validator is producing blocks

```sh [bash]
solana -ut block-production | grep <PUBKEY>
```

::: tip NOTE

You can also use the `agave-validator --ledger <PATH> monitor`
command with Frankendancer. For that, you need to build the
`agave-validator` binary from the `agave` repository.

:::

## Frankendancer Metrics

* Look at the prometheus metrics (on the same host)

```sh [bash]
curl http://localhost:7999/metrics
```

* Running the Frankendancer monitor

```sh [bash]
fdctl monitor --config ~/config.toml
```
