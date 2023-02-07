// Interface for transactional record storage. This is the raw version
// which is not thread safe. It is intended to reside on a single
// thread/CPU/tile. Presumably, a separate message layer allows access
// from other CPUs.

// Construct a storage instance. The record name argument is the backing
// record for permanent or finalized data as well as write-ahead
// logs. This record is created if it doesn't exist. Storage uses only
// one "real" record.
// Any footprint can be provided as long as it is bigger than the
// minimum. Extra space is used for the cache.
struct fd_funk;
void* fd_funk_new(void* mem,
                  ulong footprint,
                  char const* backingrecord);

FD_FN_CONST ulong fd_funk_footprint_min(void); // Minimum footprint
FD_FN_CONST ulong fd_funk_align(void);

// Join an existing store. fd_funk_new is typically called
// first. Assumes single threaded.
struct fd_funk* fd_funk_join(void* mem);

void* fd_funk_leave(struct fd_funk* store);

// Delete a storage instance. Flushes updates and closes the backing
// record.
void* fd_funk_delete(void* mem);

// Identifies a "record" or record in the storage layer. ASCII text
// isn't necessary. Compact binary identifiers are encouraged.
#define FD_FUNK_RECORDID_FOOTPRINT (64UL)
#define FD_FUNK_RECORDID_ALIGN (64UL)
struct fd_funk_recordid {
    uchar id[FD_FUNK_RECORDID_FOOTPRINT];
} __attribute__ ((aligned(FD_FUNK_RECORDID_ALIGN)));

// Identifies an ongoing transaction. A transaction represents a
// virtual state of all the records in the storage. Reads and writes
// must operate within the context of a specific transaction, and
// changes are isolated to that transaction. The intention is to
// eventually finalize the transaction, at which point the root
// transaction is updated. Transactions can also be discarded, erasing
// all pending updates. Competing/parallel transactions are allowed.
#define FD_FUNK_XACTIONID_FOOTPRINT (32UL)
#define FD_FUNK_XACTIONID_ALIGN (32UL)
struct fd_funk_xactionid {
    uchar id[FD_FUNK_XACTIONID_FOOTPRINT];
} __attribute__ ((aligned(FD_FUNK_XACTIONID_ALIGN)));

// Root or null transaction id. Used to initiate the transaction
// chain. Corresponds to all finalized data. Writes to the root
// transaction are immediately finalized and cannot be undone.
// The lifetime of this pointer is the same as the store.
struct fd_funk_xactionid const* fd_funk_root(struct fd_funk* store);

// Initiate a new transaction by forking the state of an existing
// transaction (can use root). Updates to the parent are forbidden
// after this call. The child id must not conflict with an existing
// transaction id. The parent must already exist.
void fd_funk_fork(struct fd_funk* store,
                  struct fd_funk_xactionid const* parent,
                  struct fd_funk_xactionid const* child);

// Commit all updates in the given transaction to final storage (the
// root transaction). All parent transactions in the chain are also
// finalized (but not children of the given transaction). Competing
// forked transactions are discarded. This call is safe in the
// presence of crashes, whatever that means.
void fd_funk_commit(struct fd_funk* store,
                    struct fd_funk_xactionid const* id);

// Discard all updates in the given transaction and all its children.
void fd_funk_cancel(struct fd_funk* store,
                    struct fd_funk_xactionid const* id);

// Combine a list of transactions with the same parent into a single
// transaction. Updates are applied in the specified order if there is
// a conflict.
void fd_funk_merge(struct fd_funk* store,
                   struct fd_funk_xactionid const* destid,
                   ulong source_cnt,
                   struct fd_funk_xactionid const* const* source_ids);

// Return true if the transaction is still open.
int fd_funk_isopen(struct fd_funk* store,
                   struct fd_funk_xactionid const* id);

// Update a record in the storage. Records are implicitly created/extended
// as necessary. Gaps are zero filled.
void fd_funk_write(struct fd_funk* store,
                   struct fd_funk_xactionid const* xid,
                   struct fd_funk_recordid const* recordid,
                   const void* data,
                   ulong offset,
                   ulong datalen);

// Read a record. The amount of data actually read is returned, which
// may be less then datalen if the record is shorter than expected. A -1
// is returned if an identifier is invalid.
long fd_funk_read(struct fd_funk* store,
                  struct fd_funk_xactionid const* xid,
                  struct fd_funk_recordid const* recordid,
                  void* data,
                  ulong offset,
                  ulong datalen);

// Truncate a record to the given length
void fd_funk_truncate(struct fd_funk* store,
                      struct fd_funk_xactionid const* xid,
                      struct fd_funk_recordid const* recordid,
                      ulong recordlen);

// Delete a record. Note that deletion isn't permanent until the
// transaction is committed.
void fd_funk_delete_record(struct fd_funk* store,
                           struct fd_funk_xactionid const* xid,
                           struct fd_funk_recordid const* recordid);

// Returns true if the record is in the hot cache.
char fd_funk_cache_query(struct fd_funk* store,
                         struct fd_funk_xactionid const* xid,
                         struct fd_funk_recordid const* recordid);

// Loads the record into the hot cache.
void fd_funk_cache_hint(struct fd_funk* store,
                        struct fd_funk_xactionid const* xid,
                        struct fd_funk_recordid const* recordid);
