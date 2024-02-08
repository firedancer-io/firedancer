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

### Pitfalls

When loading snapshots there are surprisingly many edge cases.

- A snapshot MAY contain different revisions of the same account.
  Revisions are ordered by the "slot" field of the account .
- Revisions of accounts MAY appear out of order (you may see a record
  at a high slot number first, then at a low slot number).
- A snapshot with two accounts at the same slot MUST be rejected by the
  loader.
- The "deleted"/"dead" state of an account also counts as a revision.
  In order to handle this correctly, the snapshot represents deleted
  accounts as accounts with most fields zero (see fd_acc_exists for a
  definition of what it means for an account to exist or be deleted).  A
  correct loader MUST remember that an account was deleted after loading
  it because it might see an older, still existing revision of it in the
  future.
- The loader MUST reject snapshots that contain an account revision
  with the "slot" number greater than the slot the snapshot was taken
  at.  (The latter is available in the bank fields of the manifest)
- The producer SHOULD NOT set the "slot" number of an account revision
  lower the actual slot number than this revision was created at.
  The loader SHOULD NOT assume that the producer behaved correctly in
  this regard because it can't verify the actual slot number the
  revision was created at.
- An account vec MAY have trailing "garbage" data.  The file content
  itself is not indicative where this trailing data starts.  Often, it
  looks deceivingly like a valid account header.  As mentioned above,
  consult the manifest for the "real" manifest size to understand where
  the garbage data starts.  The producer SHOULD NOT generate a garbage
  region.  (The only reason it exists is because Solana Labs snapshot
  production is written poorly)
- There is padding between accounts so that each account header is
  aligned by 8 bytes.  It is unclear whether padding is allowed after
  the last account in an AppendVec but _before_ the garbage data.
  The loader SHOULD gracefully handle trailing padding.  The producer
  SHOULD NOT insert padding between the last account and the garbage
  data.
  ```
  +----------------+  <-- start of AppendVec
  | account header |
  +----------------+
  | account data   |
  +----------------+
  | padding        |  <-- this edge case
  +----------------+  <-- end of file (according to bank manifest)
  | garbage        |
  +----------------+  <-- end of file (according to tar/file system)
  ```
- The snapshot manifest is unbounded.  You might run out of memory given
  a crafted snapshot.  Either while loading a snapshot, or some
  arbitrary time afterwards during a spike of allocations in epoch
  context data.  Don't forget to check that you have enough memory to
  handle any additional slot context data _after_ loading a snapshot.
- Parts of the snapshot manifest are not verifiable immediately.
  The snapshot only includes an account hash.  A malicious snapshot
  could pass account hash verification but insert malicious data that
  is only detected after some arbitrary number of epochs (during the
  epoch account hash calculation).  Validator implementations should
  make it clear to users that snapshots should be treated "trust on
  first use" style, i.e. use a snapshot from a local source whenever
  possible.

## Snapshot Restore

Snapshot loading is currently single-threaded in Firedancer.

Firedancer presently promises to handle snapshots produced by the Solana
Labs client and Firedancer.

Solana Labs v1.16 produces snapshots with version `1.2.0`.

## Snapshot Create

Firedancer cannot yet create snapshots.
