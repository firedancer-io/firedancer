#ifndef HEADER_fd_src_funk_fd_funk_rec_h
#define HEADER_fd_src_funk_fd_funk_rec_h

/* fd_funk_rec.h provides APIs for managing funk records */

#include "fd_funk_txn.h" /* Includes fd_funk_base.h */

/* FD_FUNK_REC_{ALIGN,FOOTPRINT} describe the alignment and footprint of
   a fd_funk_rec_t.  ALIGN will be a power of 2, footprint will be a
   multiple of align.  These are provided to facilitate compile time
   declarations. */

#define FD_FUNK_REC_ALIGN     (32UL)

/* FD_FUNK_REC_IDX_NULL gives the map record idx value used to represent
   NULL.  This value also set a limit on how large rec_max can be. */

#define FD_FUNK_REC_IDX_NULL (UINT_MAX)

/* A fd_funk_rec_t describes a funk record. */

struct __attribute__((aligned(FD_FUNK_REC_ALIGN))) fd_funk_rec {

  /* These fields are managed by the funk's rec_map */

  fd_funk_xid_key_pair_t pair;     /* Transaction id and record key pair */
  uint                   map_next; /* Internal use by map */

  /* These fields are managed by the user */

  uchar user[ 12 ];

  /* These fields are managed by funk.  TODO: Consider using record
     index compression here (much more debatable than in txn itself). */

  uint  next_idx;  /* Record map index of next record in its transaction */
  uint  prev_idx;  /* Record map index of previous record in its transaction */

  /* Note: use of uint here requires FD_FUNK_REC_VAL_MAX to be at most
     (1UL<<28)-1. */

  ulong val_sz  : 28;  /* Num bytes in record value, in [0,val_max] */
  ulong val_max : 28;  /* Max byte  in record value, in [0,FD_FUNK_REC_VAL_MAX], 0 if val_gaddr is 0 */
  ulong tag     :  1;  /* Used for internal validation */
  ulong val_gaddr; /* Wksp gaddr on record value if any, 0 if val_max is 0
                      If non-zero, the region [val_gaddr,val_gaddr+val_max) will be a current fd_alloc allocation (such that it is
                      has tag wksp_tag) and the owner of the region will be the record. The allocator is
                      fd_funk_alloc(). IMPORTANT! HAS NO GUARANTEED ALIGNMENT! */

};

typedef struct fd_funk_rec fd_funk_rec_t;

FD_STATIC_ASSERT( sizeof(fd_funk_rec_t) == 3U*FD_FUNK_REC_ALIGN, record size is wrong );

/* fd_funk_rec_map allows for indexing records by their (xid,key) pair.
   It is used to store all records of the last published transaction and
   the records being updated for a transaction that is in-preparation.
   Published records are stored under the pair (root,key).  (This is
   done so that publishing a transaction doesn't require updating all
   transaction id of all the records that were not updated by the
   publish.) */

#define POOL_NAME          fd_funk_rec_pool
#define POOL_ELE_T         fd_funk_rec_t
#define POOL_IDX_T         uint
#define POOL_NEXT          map_next
#define POOL_IMPL_STYLE    1
#include "../util/tmpl/fd_pool_para.c"

#define MAP_NAME              fd_funk_rec_map
#define MAP_ELE_T             fd_funk_rec_t
#define MAP_KEY_T             fd_funk_xid_key_pair_t
#define MAP_KEY               pair
#define MAP_KEY_EQ(k0,k1)     fd_funk_xid_key_pair_eq((k0),(k1))
#define MAP_KEY_HASH(k0,seed) fd_funk_xid_key_pair_hash((k0),(seed))
#define MAP_IDX_T             uint
#define MAP_NEXT              map_next
#define MAP_MAGIC             (0xf173da2ce77ecdb0UL) /* Firedancer rec db version 0 */
#define MAP_IMPL_STYLE        1
#include "../util/tmpl/fd_map_chain_para.c"

typedef fd_funk_rec_map_query_t fd_funk_rec_query_t;

/* fd_funk_rec_prepare_t represents a new record that has been
   prepared but not inserted into the map yet. See documentation for
   fd_funk_rec_prepare. */

struct _fd_funk_rec_prepare {
  fd_funk_rec_t * rec;
  uint *          rec_head_idx;
  uint *          rec_tail_idx;
};

typedef struct _fd_funk_rec_prepare fd_funk_rec_prepare_t;

FD_PROTOTYPES_BEGIN

/* fd_funk_rec_idx_is_null returns 1 if idx is FD_FUNK_REC_IDX_NULL and
   0 otherwise. */

FD_FN_CONST static inline int fd_funk_rec_idx_is_null( uint idx ) { return idx==FD_FUNK_REC_IDX_NULL; }

/* Accessors */

/* fd_funk_rec_modify attempts to modify the record corresponding to the
   given key in the given transaction. If the record does not exist,
   NULL will be returned. If the txn is NULL, the query will be done
   against funk's last published transaction (the root). On success,
   a mutable pointer to the funk record is returned.

   Assumes funk is a current local join (NULL returns NULL), txn is NULL
   or points to an in-preparation transaction in the caller's address
   space, key points to a record key in the caller's address space (NULL
   returns NULL). It is SAFE to do concurrent operations on funk with
   fd_funk_rec_modify.

   If there is contention for this record (or any records that are
   hashed to same chain as this record), the function will block the
   caller until the contention is resolved.

   A call to fd_funk_rec_modify must be followed by a call to
   fd_funk_rec_modify_publish.

   The query argument remembers the query for later validity testing.

   Important safety tips:

   1. This function can encounter records that have the ERASE flag set
   (i.e. are tombstones of erased records). fd_funk_rec_query_try will
   still return the record in this case, and the application should
   check for the flag.

   2. This function will not error if a caller attempts to modify a
   record from a non-current transaction (i.e. any funk transaction
   with a child). However, the caller should NEVER do this as it
   violates funk's invariants. */

fd_funk_rec_t *
fd_funk_rec_modify( fd_funk_t *               funk,
                    fd_funk_txn_xid_t const * xid,
                    fd_funk_rec_key_t const * key,
                    fd_funk_rec_query_t *     query );

/* fd_funk_rec_modify_publish commits any modifications to the record
   done by fd_funk_rec_modify. All notes from fd_funk_rec_modify
   apply. Calling fd_funk_rec_modify_publish is required and is
   responsible for freeing the lock on the record (and the hash
   chain). */

void
fd_funk_rec_modify_publish( fd_funk_rec_query_t * query );


/* fd_funk_rec_query_try queries the in-preparation transaction pointed to
   by txn for the record whose key matches the key pointed to by key.
   If txn is NULL, the query will be done for the funk's last published
   transaction.  Returns a pointer to current record on success and NULL
   on failure.  Reasons for failure include txn is neither NULL nor a
   pointer to a in-preparation transaction, key is NULL or not a record
   in the given transaction.

   The returned pointer is in the caller's address space if the
   return value is non-NULL.

   Assumes funk is a current local join (NULL returns NULL), txn is NULL
   or points to an in-preparation transaction in the caller's address
   space, key points to a record key in the caller's address space (NULL
   returns NULL), and no concurrent operations on funk, txn or key.
   funk retains no interest in key.  The funk retains ownership of any
   returned record.

   The query argument remembers the query for later validity testing.

   This is reasonably fast O(1).

   Important safety tip!  This function can encounter records
   that have the ERASE flag set (i.e. are tombstones of erased
   records). fd_funk_rec_query_try will still return the record in this
   case, and the application should check for the flag. */

fd_funk_rec_t *
fd_funk_rec_query_try( fd_funk_t *               funk,
                       fd_funk_txn_xid_t const * xid,
                       fd_funk_rec_key_t const * key,
                       fd_funk_rec_query_t *     query );

/* fd_funk_rec_query_test returns SUCCESS if a prior query still has a
   valid result. The coding pattern is:

     for(;;) {
       fd_funk_rec_query_t query[1];
       fd_funk_rec_t * rec = fd_funk_rec_query_try( funk, txn, key, query );
       ... Optimistically read record value ...
       if( fd_funk_rec_query_test( query ) == FD_FUNK_SUCCESS ) break;
       ... Clean up and try again ...
     }
*/

int fd_funk_rec_query_test( fd_funk_rec_query_t * query );

/* fd_funk_rec_query_try_global is the same as fd_funk_rec_query_try but
   will query txn's ancestors for key from youngest to oldest if key is
   not part of txn.  As such, the txn of the returned record may not
   match txn but will be the txn of most recent ancestor with the key
   otherwise.   If xid_out!=NULLL, *xid_out is set to the XID in which
   the record was created.

   This is reasonably fast O(in_prep_ancestor_cnt).

   Important safety tip!  This function can encounter records
   that have the ERASE flag set (i.e. are tombstones of erased
   records). fd_funk_rec_query_try_global will return a NULL in this case
   but still set *txn_out to the relevant transaction. This behavior
   differs from fd_funk_rec_query_try. */
fd_funk_rec_t const *
fd_funk_rec_query_try_global( fd_funk_t const *         funk,
                              fd_funk_txn_xid_t const * xid,
                              fd_funk_rec_key_t const * key,
                              fd_funk_txn_xid_t *       xid_out,
                              fd_funk_rec_query_t *     query );

/* fd_funk_rec_query_copy queries the in-preparation transaction pointed to
   by txn for the record whose key matches the key pointed to by key.

   The contents of the record are safely copied into space allocated
   with the valloc, and a pointer to that space is returned. If there
   is an error, NULL is returned. The size of the record is returned
   in sz_out. */

fd_funk_rec_t const *
fd_funk_rec_query_copy( fd_funk_t *               funk,
                        fd_funk_txn_xid_t const * xid,
                        fd_funk_rec_key_t const * key,
                        fd_valloc_t               valloc,
                        ulong *                   sz_out );

/* fd_funk_rec_{pair,xid,key} returns a pointer in the local address
   space of the {(transaction id,record key) pair,transaction id,record
   key} of a live record.  Assumes rec points to a live record in the
   caller's address space.  The lifetime of the returned pointer is the
   same as rec.  The value at the pointer will be constant for its
   lifetime. */

FD_FN_CONST static inline fd_funk_xid_key_pair_t const * fd_funk_rec_pair( fd_funk_rec_t const * rec ) { return &rec->pair;    }
FD_FN_CONST static inline fd_funk_txn_xid_t const *      fd_funk_rec_xid ( fd_funk_rec_t const * rec ) { return rec->pair.xid; }
FD_FN_CONST static inline fd_funk_rec_key_t const *      fd_funk_rec_key ( fd_funk_rec_t const * rec ) { return rec->pair.key; }

/* fd_funk_rec_prepare creates an unpublished funk record entry.  This
   is the first step to adding a funk record to a transaction.  Record
   entry acquisition may fail if the record object pool is exhausted
   (FD_FUNK_ERR_REC) or the transaction is not writable
   (FD_FUNK_ERR_FROZEN).  The returned record entry (located in funk
   shared memory) is then either be cancelled or published by the
   caller.  This record is invisible to funk query or record-iteration
   operations until published.  Concurrent record preparation is fine. */

fd_funk_rec_t *
fd_funk_rec_prepare( fd_funk_t *               funk,
                     fd_funk_txn_xid_t const * xid,
                     fd_funk_rec_key_t const * key,
                     fd_funk_rec_prepare_t *   prepare,
                     int *                     opt_err );

/* fd_funk_rec_publish makes a prepared record globally visible.  First,
   registers a record with the txn's record list, then inserts it into
   the record map.  Concurrent record publishing is fine, even to the
   same transaction.  Crashes the application with FD_LOG_CRIT if the
   caller attempts to publish the same (txn,xid) key twice. */

void
fd_funk_rec_publish( fd_funk_t *             funk,
                     fd_funk_rec_prepare_t * prepare );

/* fd_funk_rec_cancel returns an unpublished funk record entry back to
   the record object pool, invalidating the prepare struct.  The caller
   cleans up any resources associated with the record (e.g. funk_val)
   before calling this function. */

void
fd_funk_rec_cancel( fd_funk_t *             funk,
                    fd_funk_rec_prepare_t * prepare );

/* fd_funk_rec_clone copies a record from an ancestor transaction
   to create a new record in the given transaction. The record can be
   modified afterward and must then be published.

   NOTE: fd_funk_rec_clone is NOT thread safe and should not be used
   concurrently with other funk read/write operations. */

fd_funk_rec_t *
fd_funk_rec_clone( fd_funk_t *               funk,
                   fd_funk_txn_xid_t const * xid,
                   fd_funk_rec_key_t const * key,
                   fd_funk_rec_prepare_t *   prepare,
                   int *                     opt_err );

/* Misc */

/* fd_funk_rec_verify verifies the record map.  Returns FD_FUNK_SUCCESS
   if the record map appears intact and FD_FUNK_ERR_INVAL if not (logs
   details).  Meant to be called as part of fd_funk_verify.  As such, it
   assumes funk is non-NULL, fd_funk_{wksp,txn_map,rec_map} have been
   verified to work and the txn_map has been verified. */

int
fd_funk_rec_verify( fd_funk_t * funk );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_funk_fd_funk_rec_h */
