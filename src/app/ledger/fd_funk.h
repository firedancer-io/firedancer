// Interface for transactional file storage. This is the raw version
// which is not thread safe. It is intended to reside on a single
// thread/CPU/tile. Presumably, a separate message layer allows access
// from other CPUs.

// Construct a storage instance. The file name argument is the backing
// file for permanent or finalized data as well as write-ahead
// logs. This file is created if it doesn't exist. Storage uses only
// one "real" file.
struct fd_funk;
void fd_funk_attach(struct fd_funk* store,
                    const char* backingfile);

extern unsigned long fd_funk_footprint(); 
extern unsigned long fd_funk_align(); 

// Detach a storage instance. Flushes updates and closes the backing
// file.
void fd_funk_detach(struct fd_funk* store);

// Identifies a "file" or record in the storage layer. ASCII text
// isn't necessary. Compact binary identifiers are encouraged.
#define fd_funk_fileid_len 64
struct fd_funk_fileid {
    char id[fd_funk_fileid_len];
};

// Identifies an ongoing transaction. A transaction represents a
// virtual state of all the files in the storage. Reads and writes
// must operate within the context of a specific transaction, and
// changes are isolated to that transaction. The intention is to
// eventually finalize the transaction, at which point the root
// transaction is updated. Transactions can also be discarded, erasing
// all pending updates. Competing/parallel transactions are allowed.
#define fd_funk_xactionid_len 32
struct fd_funk_xactionid {
    char id[fd_funk_xactionid_len];
};

// Root or null transaction id. Used to initiate the transaction
// chain. Corresponds to all finalized data. Writes to the root
// transaction are immediately finalized and cannot be undone.
extern struct fd_funk_xactionid* fd_funk_xactionid_root;

// Initiate a new transaction by forking the state of an existing
// transaction (can use root). Updates to the parent are forbidden
// after this call. The child id must not conflict with an existing
// transaction id.
extern void fd_funk_fork_xaction(struct fd_funk* store,
                                 struct fd_funk_xactionid* parent,
                                 struct fd_funk_xactionid* child);

// Commit all updates in the given transaction to final storage (the
// root transaction). All parent transactions in the chain are also
// finalized (but not children of the given transaction). Competing
// forked transactions are discarded.
extern void fd_funk_finalize_xaction(struct fd_funk* store,
                                     struct fd_funk_xactionid* id);

// Discard all updates in the given transaction and all its children.
extern void fd_funk_discard_xaction(struct fd_funk* store,
                                    struct fd_funk_xactionid* id);

// Combine a list of transactions with the same parent into a single
// transaction. Updates are applied in the specified order if there is
// a conflict.
extern void fd_funk_merge_xaction(struct fd_funk* store,
                                  struct fd_funk_xactionid* destid,
                                  unsigned int numsources,
                                  struct fd_funk_xactionid** sourceids);

// Update a file in the storage. Files are implicitly created/extended
// as necessary. Gaps are zero filled.
extern void fd_funk_write_file(struct fd_funk* store,
                               struct fd_funk_xactionid* xid,
                               struct fd_funk_fileid* fileid,
                               const void* data,
                               unsigned long offset,
                               unsigned long datalen);

// Read a file. The amount of data actually read is returned, which
// may be less then datalen if the file is shorter than expected. A -1
// is returned if an identifier is invalid.
extern long fd_funk_read_file(struct fd_funk* store,
                              struct fd_funk_xactionid* xid,
                              struct fd_funk_fileid* fileid,
                              void* data,
                              unsigned long offset,
                              unsigned long datalen);

// Truncate a file to the given length
extern void fd_funk_truncate_file(struct fd_funk* store,
                                  struct fd_funk_xactionid* xid,
                                  struct fd_funk_fileid* fileid,
                                  unsigned long filelen);

// Delete a file. Note that deletion isn't permanent until the
// transaction is committed.
extern void fd_funk_delete_file(struct fd_funk* store,
                                struct fd_funk_xactionid* xid,
                                struct fd_funk_fileid* fileid);

// Returns true if the file is in the hot cache.
extern char fd_funk_cache_query(struct fd_funk* store,
                                struct fd_funk_xactionid* xid,
                                struct fd_funk_fileid* fileid);

// Loads the file into the hot cache.
extern void fd_funk_cache_hint(struct fd_funk* store,
                               struct fd_funk_xactionid* xid,
                               struct fd_funk_fileid* fileid);
