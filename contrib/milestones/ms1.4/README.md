# Firedancer Milestone 1.4 Setup

This milestone involves setting up 2 kinds of nodes, the **leader**
and the **follower**.  Here is a general step-by-step overview of
how to set this up.

```bash
mkdir -p ~/ms1.4
cd ~/ms1.4/
```

## Build the binaries

Clone the repository at the `ms1.4` branch and build.  This needs to
happen on all hosts that will participate in the cluster and the host
where the benchmarking program will run.

```bash
git clone https://github.com/firedancer-io/firedancer.git
cd firedancer/
git checkout origin/ms1.4
git submodule update --init
MACHINE=linux_gcc_icelake make -j fdctl fddev
```

## Create a genesis

This is done as a separate process to save the faucet key for funding
accounts later on in the process.  This needs to happen on the **leader**
host.

```bash
# Run the following to put the binaries in PATH
# export PATH=$HOME/ms1.4/firedancer/build/linux/gcc/icelake/bin:$PATH
build/linux/gcc/icelake/bin/fddev configure init all --config contrib/milestones/ms1.4/leader.toml
# Copy the faucet somewhere
cp /dev/shm/fd1/faucet.json ~/ms1.4/faucet.json
# We also need to tar the genesis
cd /dev/shm/fd1/ledger && tar cjf genesis.tar.bz2 genesis.bin rocksdb/ && cd $OLDPWD
```

## Start the leader

```bash
build/linux/gcc/icelake/bin/fddev --no-configure --config contrib/milestones/ms1.4/leader.toml
```

We can monitor the leader startup using the `solana -u <URL> validators` and
`solana -u <URL> epoch-info` commands where `URL=http://<LEADER-IP-ADDRESS>:8899`.

## Start the follower(s)

For each follower, we need to create and fund a keypair.  We need the `solana`
and `solana-keygen` binaries for this, which we can build from the [Agave repository](https://github.com/anza-xyz/agave.git).
YoWeu need to copy over the `~/ms1.4/faucet.json` to the **follower** hosts.

```bash
solana-keygen new --no-bip39-passphrase -o id.json > /dev/null 2>&1
# URL=http://<LEADER-IP-ADDRESS>:8899
solana -u <URL> transfer -k ~/ms1.4/faucet.json --allow-unfunded-recipient id.json 10
```

Update the `follower.toml` file with the correct values for `gossip.entrypoint` (from
where the leader is running) and `consensus.identity_path` (from where the part above)
and start up the follower:

```bash
build/linux/gcc/icelake/bin/fdctl configure init all --config contrib/milestones/ms1.4/follower.toml
build/linux/gcc/icelake/bin/fddev run --config contrib/milestones/ms1.4/follower.toml
```

We can monitor when the followers have joined the cluster with the `solana -u <URL> gossip` commmand.

## Start the workout

Once all the nodes have joined the cluster (note that they will not be voting), we can
start the `hiit` workout.  It will send a whole bunch of transactions to the leader.
This needs to run on another host with at least 22 cores.

```bash
sudo build/linux/gcc/icelake/bin/fddev hiit --tpu-ip <LEADER-IP-ADDRESS> \
                                            --rpc-ip <LEADER-IP-ADDRESS> \
                                            --num-benchg   12            \
                                            --num-benchs   8             \
                                            --affinity     8-30          \
                                            --num-accounts 9000          \
                                            --tpu-port     9007
```

Once it starts up, we should be able to see a transaction per seconds number in the output.
There will be a bit of jitter in the begginning but it should settle down on a consistent
rate eventually.  To use UDP instead of QUIC, replace the `--tpu-port 9007` argument with
`--no-quic`.  After some amount of time, the followers will start falling behind, but the
leader should maintain the TPS.
