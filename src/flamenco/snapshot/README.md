# Snapshot Handling

Solana snapshots contain a serialization of the implicit "bank" state
and a copy of some or all accounts.

## File Format

As of snapshot version 1.2.0, the format is a Zstandard compressed TAR
stream (OLDGNU magic).  The TAR stream should only contain regular files
with path length <= 99 chars.

There are no framing restrictions on the Zstandard stream: A valid
snapshot may be a single huge zstd frame, however this is discouraged.
Ideally, a snapshot should consist of multiple frames up to 100 MB
compressed size.  This allows for multi-threaded decompression.

### Version File

The first file in the archive is at path `version`.
It contains the 5 byte ASCII string `1.2.0`.

### Manifest File

The manifest file is at path `snapshots/<slot>/<slot>`, where `<slot>`
is replaced with the slot number in base-10 encoding.

It is a huge Bincode blob (~300 MB) corresponding to Firedancer type
`fd_solana_manifest_t`.

It contains the following information:
- The implicit "bank" state
- Various consensus information (such as previous block metadata)
- Information about the append vec files that follow

### Account Vec Files

All other files in the archive are account vec files that each contain
a vector of accounts.  These are at path `accounts/<slot>.<id>` where
`<slot>` where slot is used for sorting revisions of an account, and
`<id>` is some unique number in case there are multiple account vec
files for the same slot.

An account may appear in multiple account vecs, but the slot number must
be different each time.  The highest slot number for an account decides
the final content of the account.  It is invalid to specify an account
multiple times for the same slot number.

Each account vec may have arbitrary trailing data past the offset
specified in the manifest file.

**Implementation Detail: Solana Labs**

- Solana Labs will typically produce account vec files where some
  accounts appear as multiple revisions for different slots.
- As of Solana v1.16, some account vecs will contain trailing garbage.
  This might get fixed in a future release.

**Implementation Detail: Firedancer**

- Firedancer currently only includes each account once.
- Firedancer currently always sets the account vec slot number to `0`.

## Snapshot Restore

Snapshot loading is currently single-threaded in Firedancer.

Firedancer presently promises to handle snapshots produced by the Solana
Labs client and Firedancer.

Solana Labs v1.16 produces snapshots with version `1.2.0`.

## Snapshot Create

Firedancer cannot yet create snapshots.
