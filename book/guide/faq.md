# Frequently Asked Questions

::: details What hardware do I need to run Frankendancer?

The current Frankendancer hardware requirements are the same
as that of an Agave validator. Refer to the [Hardware](./getting-started.md#hardware-requirements)
section in the [Getting Started](./getting-started.md) guide
for more details.

:::

::: details How can I obtain the Frankendancer binaries?

Frankendancer does not currently provide pre-built binaries.
It is recommended to build the binaries on the same host where
you are planning to run the validator. Frankendancer detects
system properties and tries to build a binary tuned for the
particular host. Take a look at the [getting started](./getting-started.md)
guide for requirements and instructions.

:::

::: details What branch or tag should I build from?

You should checkout and build from a tagged release. The latest
version is `__FD_LATEST_VERSION__`. For more information, refer
to the [releases](./getting-started.md#releases) section.

:::

::: details How do I resolve errors encountered while starting up Frankendancer?

The Frankendancer binary `fdctl` tries to provide helpful error
messages to identify the problem and sometimes even suggests
solutions. Take a look at the [troubleshooting](./troubleshooting.md)
guide for some easy steps that can mitigate some common issues.

:::

::: details Can Agave and Frankendancer use the same ledger and snapshots?

Yes, Frankendancer is fully compatible with both the snapshot
and the ledger formats of the Agave validator.

:::

::: details How can I monitor the status of my Frankendancer node?

You can use most of the regular monitoring tools and commands
that you typically would use with an Agave validator to monitor
Frankendancer as well. Refer to the [monitoring](./monitoring.md)
guide for some helpful commands.

:::

::: details Why is my node still delinquent?

There could be several reasons, some of which include the validator
being unable to catchup and the validator not voting properly among
others. Take a look at the [tuning](./tuning.md) guide for some
tips on how to configure Frankendancer to increase the performance
of the replay stage so the validator catches up faster. Also make
sure that your node is staked and the stake is active.

:::
