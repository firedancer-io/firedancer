# Agave Snapshots

## File Format

`snapshot.tar.zst` is an Agave-specific undocumented file format
containing all state required to replay and produce blocks.

Notably, this includes:
- Manifest (bank fields)
  - Epoch stakes (currently active stake weights)
- Status cache (recently executed transactions)
- Accounts

The outer framing of the snapshot stream is a Zstandard-compressed TAR
stream. The TAR format is GNU, the compression level is typically 1
(512 KiB window size).

```console
$ tar -I zstd \
  -tf snapshot-407582142-563aQbfBAzWSWSRMe8P5S41Aqn1Qc4UgsfdW4LEtke6T.tar.zst \
  | head -n 10
version
snapshots/
snapshots/status_cache
snapshots/407582142
snapshots/407582142/407582142
accounts/389328849.72670
accounts/402925643.38879
accounts/322026661.73741
...
```

## Security

Agave snapshots are not cryptographically verifiable.

Validator operators must only boot from trusted snapshots.

The snapshot filename includes a hash of all accounts (`blake3(accounts_lthash)`).
In theory, the snapshot loader could check the hash of accounts while
loading and then compare this hash to LtHash values observed in gossip.

However, status cache and bank fields cannot be hashed because they are
non-deterministic. A malicious snapshot could cause a node that boots
off this snapshot to crash or confirm invalid state transitions.

This is an inherent limitation of the Agave snapshot file format. It
cannot be fixed without protocol changes.

## Hard Forks

Solana hard forks are an emergency feature used to re-synchronize a
validator cluster after a consensus failure.

Hard forks can be manually inserted when creating a snapshot.
The following Agave command creates a snapshot at a given slot, and then
inserts a hard fork at that same slot.

```
agave-ledger-tool create-snapshot --hard-fork SLOT_NUMBER -- SLOT_NUMBER
```

Firedancer only processes hard forks at the snapshot slot. Earlier or
later scheduled hard forks are ignored.
