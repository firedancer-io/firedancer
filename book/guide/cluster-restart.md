# Cluster Restart

This page explains the steps needed to be taken to restart a Frankendancer validator in the event of a cluster halt.

<b> IMPORTANT NOTE: </b> This is an example, please refer to the Cluster Restart Instructions disseminated to retrieve restart parameters (Validator version, Snapshot slot, Restart slot, Shred version and Expected bank hash) in the event of an actual cluster restart.

## Summary

Block production on Solana Testnet has halted at approximately XXXX UTC on DD MMM YYYY.

|                    |                            |
| ------------------ | -------------------------- |
| Validator version  | Frankendancer: vX.XXX.XXXX |
| Snapshot slot      | XXX_XXX_XXX                |
| Restart slot       | XXX_XXX_XXX                |
| Shred version      | XXXX                       |
| Expected bank hash | XXXX                       |

## Performing a Cluster Restart with Frankendancer

### 1. Stop the Running Frankendancer Validator

Stop the Frankendancer validator by killing the fdctl process.

```
sudo pkill fdctl
```

If you are running it as a service, we recommend you to check that it is inactive.

```
systemctl stop frankendancer.service
```

### 2. Confirm Latest Optimistic Slot

Build the agave-ledger-tool within the agave submodule, and then use it to verify your latest observed optimistic slot:

```
agave-ledger-tool -l /path/to/ledger latest-optimistic-slots
```

If your latest optimistic slot is lower than what is listed in the summary table, it is likely your node crashed before it was able to observe the latest supermajority. In this case, move on to Step 4.

Important: <b> DO NOT </b> delete your ledger directory.

### 3. Create a Snapshot

Navigate to the snapshots path `[snapshots.path]` specified within fd_config.toml. If not specified, the snapshots are stored and retrieved from `[ledger.path]` by default.

Create a snapshot starting from the restart slot using the command:

```
agave-ledger-tool --ledger /path/to/ledger \
                  --snapshot-archive-path /path/to/ledger/snapshots \
                  --incremental-snapshot-archive-path /path/to/ledger/incremental/snapshots \
                  create-snapshot RESTART_SLOT /path/to/ledger/snapshots \
                  --hard-fork RESTART_SLOT
```

If you have a custom accounts path, add `--accounts /path/to/accounts \` before `--hard-fork RESTART_SLOT`

Upon creating the snapshot, you should see the following at the end:

```
Successfully created snapshot for slot 6024,
hash 2XuGPTvYRLG7c2WEf6p6bqszzUMKBJX4uz3WP7bDLHkh:
/home/fd/ledger/snapshot-6024-BaYtdt2unuKtMisBtrM4wUpQk2QKj1AKRcktF5zPhNCL.tar.zst
Shred version: 4919
```

After the new snapshot has been created, create a temporary folder, and move all other snapshots and incremental snapshots to that folder.

### 4. Configure Restart Parameters

It is recommended to restart from a local snapshot when the cluster is halted. In this case, refer to
[Restarting from a local snapshot](#config-restarting-from-a-local-snapshot)

There are some other cases which might require you to restart from a downloaded snapshot:

1. If your last observed optimistically confirmed slot is less than the restart slot
2. If your ledger history is corrupt or you have removed the ledger
3. If your node is not part of the cluster restart, meaning that the cluster is already restarted and is running for some time, it is likely that your Frankendancer node will be far behind

In these cases, refer to [Restarting from a downloaded snapshot](#config-restarting-from-a-downloaded-snapshot).

#### Config: Restarting from a local snapshot

Update the `fd_config.toml` file with these restart parameters. These values should be verified against the output of the agave-ledger-tool command and the cluster restart document:

```
[consensus]
    ...
    genesis_fetch = false
    snapshot_fetch = false

    expected_bank_hash = NEW_BANK_HASH            # NEW! REMOVE AFTER THIS RESTART
    wait_for_supermajority_at_slot = RESTART_SLOT     # NEW! REMOVE AFTER THIS RESTART
    expected_shred_version = NEW_SHRED_VERSION    # NEW! REMOVE AFTER THIS RESTART
```

Remember to remove the parameters after restart if you are running it as a service.

If this step fails, try retrieving the snapshot from a known validator below.

### 5. Update Frankendancer Validator Version

Patches (if any)

### 6. Restart the Frankendancer Validator

Start the Frankendancer validator either by restarting the service or manually with

```
fdctl configure init all --config fd_config.toml &&
fdctl run --config fd_config.toml
```

### 7. Monitor Cluster Restart

As Frankendancer boots, it will load the snapshot at the new restart slot and wait for supermajority stake to be reached before producing and validating new blocks.

- If the activated stake has not reached 80%, the Agave logs will output:

```
INFO solana_core::validator] Waiting for 80% of activated stake at slot 6024 to be in gossip...
```

- If you have RPC enabled locally, query solana for the current slot:

```
solana -ul slot
```

- The active stake percentage in the cluster is also visible in the logs:

```
78.132% of active stake visible in gossip
21.868% of active stake has the wrong shred version in gossip
  7.289% - validator_identity_key
  7.289% - validator_identity_key
  7.289% - validator_identity_key
```

- Once supermajority is reached, the hard fork will be processed:

```
[ERROR solana_metrics::metrics] datapoint: tower_error
error="Unable to restore tower: The tower is useless because of new hard fork: 6024"
```

Make sure that Frankendancer logs and cluster metrics are progressing healthily. Standard ways of obtaining metrics from Agave CLI commands apply. Refer to the [monitoring](/guide/monitoring.md) section of the Book to learn more.

## Appendix

#### Config: Restarting from a downloaded snapshot

Note: This method is not recommended, and should only be performed if your local ledger is corrupt or you are unable to produce a snapshot for the restart slot.

Update the `fd_config.toml` file to fetch a snapshot from a known validator:

```
[consensus]
    ...
    genesis_fetch = false
    snapshot_fetch = true

    wait_for_supermajority_at_slot = RESTART_SLOT     # NEW! REMOVE AFTER THIS RESTART
    expected_bank_hash = NEW_BANK_HASH            # NEW! REMOVE AFTER THIS RESTART
    expected_shred_version = NEW_SHRED_VERSION    # NEW! REMOVE AFTER THIS RESTART
    known_validators = [KNOWN_VALIDATOR]          # NEW! REMOVE AFTER THIS RESTART
```

Remember to remove the parameters after restart and modify to `snapshot_fetch = false` after the snapshot is downloaded.

## FAQ

1. How do i identify my local latest optimistically confirmed slot?

In Agave 1.14>=, use the ledger tool to determine the latest optimistically confirm slot that your validator has observed:

```
agave-ledger-tool -l /path/to/ledger latest-optimistic-slots
```

Solana metrics also exposes this slot in the logs. In other agave versions, run:

```
grep "optimistic_slot slot=" /path/to/validator/log | tail
```

2. I’m getting a blockstore error received index XXX >= slot.last_index, what should i do?

This means that your Frankendancer validator has produced blocks that were generated after the restart slot (latest optimistically confirmed slot) and before the network halted.

You can determine the state of your blockstore and slots that your ledger has data for by running the following command:

```
agave-ledger-tool bounds -l /path/to/ledger
```

This should output:

```
Ledger has data for XXX slots XXX to XXX
  with XXX rooted slots from XXX to XXX
  and XXX slots past the last root
```

Proceed to prune the slots that are causing the conflict with:

```
agave-ledger-tool purge PURGE_START_SLOT
```

This deletes a range of slots from the ledger, starting from `PURGE_START_SLOT` inclusive, until the highest slot in the ledger.

3. I am getting a file descriptor error when running agave-ledger-tool

You may need to increase your open file limits. One way to drop into a shell with higher limits is

```
bash -c "prlimit --pid=$$ --nofile=1000000:1000000"
```

If you are unable to increase the maximum open file descriptor limit, try

```
prlimit --pid=$$ --memlock=unlimited
```
