#ifndef HEADER_fd_src_discof_accdb_fd_accdb_cache_h
#define HEADER_fd_src_discof_accdb_fd_accdb_cache_h

#include "../../util/fd_util_base.h"

struct fd_accdb_cache;
typedef struct fd_accdb_cache fd_accdb_cache_t;

struct fd_accdb_cache_entry {
  uchar   owner[ 32UL ];
  ulong   lamports;
  ulong   data_len;
  uchar * data;

  int     dirty;
};

typedef struct fd_accdb_cache_entry fd_accdb_cache_entry_t;

FD_PROTOTYPES_BEGIN

/* fd_accdb_cache_acquire brings all of the requested accounts as-of the
   given bank_idx into the cache, and refcnts them in the cache so they
   cannot be evicted until later released.  If any of the requested
   accounts is not found, or has a balance of zero, then the function
   returns -1 and no accounts are acquired, otherwise returns 0.

   bank_idx is the bank index from replay to query as-of, and must exist
   for the entire duration of the acquire call, meaning, whoever is
   acquiring must have a refcnt on the bank with index bank_idx, and not
   release it until after the accounts are acquired.  It is safe to
   release the bank after the acquire call returns, and this will not
   cause the acquired accounts to be evicted from the cache.

   pubkeys_cnt is the number of accounts to acquire, and pubkeys is an
   array of pointers to the 32-byte pubkeys of the accounts to acquire.
   writable is an array of flags indicating whether each corresponding
   account in pubkeys is being acquired for write (1) or read (0).  If
   an account is being acquired for write, you may modify the fields in
   the returned cache entry, including the data.
   
    then the cache assumes
   already
   If you intend to modify the account data in-place, you must acquire
   it for write.

   out_entries is an array of pubkeys_cnt cache entries to be filled in
   with the acquired accounts.  The cache will fill the owner, lamports,
   data_len, and data fields of each entry if the acquire is successful.
    
   The dirty field is not modified by the acquire call, and is set to 0
   by the cache when an entry is first brought into the cache.  

int
fd_accdb_cache_acquire( fd_accdb_cache_t *       cache,
                        ulong                    bank_idx,
                        ulong                    pubkeys_cnt,
                        uchar const * const *    pubkeys,
                        int *                    writable,
                        fd_accdb_cache_entry_t * out_entries );

void
fd_accdb_cache_release( fd_accdb_cache_t *       cache,
                        fd_accdb_cache_entry_t * entry );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_accdb_fd_accdb_cache_h */
