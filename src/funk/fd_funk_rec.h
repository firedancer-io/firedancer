#ifndef HEADER_fd_src_funk_fd_funk_rec_h
#define HEADER_fd_src_funk_fd_funk_rec_h

/* This provides APIs for managing funk records.  It is generally not
   meant to be included directly.  Use fd_funk.h instead.

   The following APIs are thread safe and can be interleaved arbirarily
   across threads:
     fd_funk_rec_query_try
     fd_funk_rec_query_test
     fd_funk_rec_query_try_global
     fd_funk_rec_prepare
     fd_funk_rec_publish
     fd_funk_rec_cancel
     fd_funk_rec_remove
*/

#include "fd_funk_txn.h" /* Includes fd_funk_base.h */

/* FD_FUNK_REC_{ALIGN,FOOTPRINT} describe the alignment and footprint of
   a fd_funk_rec_t.  ALIGN will be a power of 2, footprint will be a
   multiple of align.  These are provided to facilitate compile time
   declarations. */

#define FD_FUNK_REC_ALIGN     (64UL)

/* FD_FUNK_REC_FLAG_* are flags that can be bit-ored together to specify
   how records are to be interpreted.  The 5 most significant bytes of a
   rec's flag are reserved to be used in conjunction with the ERASE flag.

   - ERASE indicates a record in an in-preparation transaction should be
   erased if and when the in-preparation transaction is published. If
   set on a published record, it serves as a tombstone.
   If set, there will be no value resources used by this record. */

#define FD_FUNK_REC_FLAG_ERASE (1UL<<0)

/* FD_FUNK_REC_IDX_NULL gives the map record idx value used to represent
   NULL.  This value also set a limit on how large rec_max can be. */

#define FD_FUNK_REC_IDX_NULL (ULONG_MAX)

/* A fd_funk_rec_t describes a funk record. */

struct __attribute__((aligned(FD_FUNK_REC_ALIGN))) fd_funk_rec {

  /* These fields are managed by the funk's rec_map */

  fd_funk_xid_key_pair_t pair;     /* Transaction id and record key pair */
  ulong                  map_next; /* Internal use by map */
  ulong                  map_hash; /* Internal use by map */

  /* These fields are managed by funk.  TODO: Consider using record
     index compression here (much more debatable than in txn itself). */

  ulong prev_idx;  /* Record map index of previous record in its transaction */
  ulong next_idx;  /* Record map index of next record in its transaction */
  uint  txn_cidx;  /* Compressed transaction map index (or compressed FD_FUNK_TXN_IDX if this is in the last published) */
  uint  tag;       /* Internal use only */
  ulong flags;     /* Flags that indicate how to interpret a record */

  /* Note: use of uint here requires FD_FUNK_REC_VAL_MAX to be at most
     UINT_MAX. */

  uint  val_sz;    /* Num bytes in record value, in [0,val_max] */
  uint  val_max;   /* Max byte  in record value, in [0,FD_FUNK_REC_VAL_MAX], 0 if erase flag set or val_gaddr is 0 */
  ulong val_gaddr; /* Wksp gaddr on record value if any, 0 if erase flag set or val_max is 0
                      If non-zero, the region [val_gaddr,val_gaddr+val_max) will be a current fd_alloc allocation (such that it is
                      has tag wksp_tag) and the owner of the region will be the record. The allocator is
                      fd_funk_alloc(). IMPORTANT! HAS NO GUARANTEED ALIGNMENT! */

  /* Padding to FD_FUNK_REC_ALIGN here */
};

typedef struct fd_funk_rec fd_funk_rec_t;

FD_STATIC_ASSERT( sizeof(fd_funk_rec_t) == 2U*FD_FUNK_REC_ALIGN, record size is wrong );

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
#define MAP_NEXT              map_next
#define MAP_MEMO              map_hash
#define MAP_MAGIC             (0xf173da2ce77ecdb0UL) /* Firedancer rec db version 0 */
#define MAP_MEMOIZE           1
#define MAP_IMPL_STYLE        1
#include "../util/tmpl/fd_map_chain_para.c"
#undef  MAP_MEMOIZE
#undef  MAP_HASH

typedef fd_funk_rec_map_query_t fd_funk_rec_query_t;

/* fd_funk_rec_prepare_t represents a new record that has been
   prepared but not inserted into the map yet. See documentation for
   fd_funk_rec_prepare. */

struct _fd_funk_rec_prepare {
  fd_funk_t *     funk;
  fd_wksp_t *     wksp;
  fd_funk_rec_t * rec;
  ulong *         rec_head_idx;
  ulong *         rec_tail_idx;
};

typedef struct _fd_funk_rec_prepare fd_funk_rec_prepare_t;

FD_PROTOTYPES_BEGIN

/* fd_funk_rec_idx_is_null returns 1 if idx is FD_FUNK_REC_IDX_NULL and
   0 otherwise. */

FD_FN_CONST static inline int fd_funk_rec_idx_is_null( ulong idx ) { return idx==FD_FUNK_REC_IDX_NULL; }

/* Accessors */

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

fd_funk_rec_t const *
fd_funk_rec_query_try( fd_funk_t *               funk,
                       fd_funk_txn_t const *     txn,
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

/* fd_funk_rec_query_try_global is the same as fd_funk_rec_query_try but will
   query txn's ancestors for key from youngest to oldest if key is not
   part of txn.  As such, the txn of the returned record may not match
   txn but will be the txn of most recent ancestor with the key
   otherwise. *txn_out is set to the transaction where the record was
   found.

   This is reasonably fast O(in_prep_ancestor_cnt).

   Important safety tip!  This function can encounter records
   that have the ERASE flag set (i.e. are tombstones of erased
   records). fd_funk_rec_query_try_global will return a NULL in this case
   but still set *txn_out to the relevant transaction. This behavior
   differs from fd_funk_rec_query_try. */
fd_funk_rec_t const *
fd_funk_rec_query_try_global( fd_funk_t *               funk,
                              fd_funk_txn_t const *     txn,
                              fd_funk_rec_key_t const * key,
                              fd_funk_txn_t const **    txn_out,
                              fd_funk_rec_query_t *     query );

/* fd_funk_rec_query_copy queries the in-preparation transaction pointed to
   by txn for the record whose key matches the key pointed to by key.

   The contents of the record are safely copied into space allocated
   with the valloc, and a pointer to that space is returned. If there
   is an error, NULL is returned. The size of the record is returned
   in sz_out. */

fd_funk_rec_t const *
fd_funk_rec_query_copy( fd_funk_t *               funk,
                        fd_funk_txn_t const *     txn,
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

/* fd_funk_rec_prepare prepares to insert a new record. This call just
   allocates a record from the pool and initializes it.
   The application should then fill in the new
   value. fd_funk_rec_publish actually does the map insert and
   should be called once the value is correct. */

fd_funk_rec_t *
fd_funk_rec_prepare( fd_funk_t *               funk,
                     fd_funk_txn_t *           txn,
                     fd_funk_rec_key_t const * key,
                     fd_funk_rec_prepare_t *   prepare,
                     int *                     opt_err );

/* fd_funk_rec_publish inserts a prepared record into the record map. */

void
fd_funk_rec_publish( fd_funk_rec_prepare_t * prepare );

/* fd_funk_rec_cancel returns a prepared record to the pool without
   inserting it. */

void
fd_funk_rec_cancel( fd_funk_rec_prepare_t * prepare );

/* fd_funk_rec_clone copies a record from an ancestor transaction
   to create a new record in the given transaction. The record can be
   modified afterward and must then be published. */

fd_funk_rec_t *
fd_funk_rec_clone( fd_funk_t *               funk,
                   fd_funk_txn_t *           txn,
                   fd_funk_rec_key_t const * key,
                   fd_funk_rec_prepare_t *   prepare,
                   int *                     opt_err );

/* fd_funk_rec_is_full returns true if no more records can be
   allocated. */

int
fd_funk_rec_is_full( fd_funk_t * funk );

/* fd_funk_rec_remove removes the live record with the
   given (xid,key) from funk. Returns FD_FUNK_SUCCESS (0) on
   success and a FD_FUNK_ERR_* (negative) on failure.  Reasons for
   failure include:

     FD_FUNK_ERR_INVAL - bad inputs (NULL funk, NULL xid)

     FD_FUNK_ERR_KEY - the record did not appear to be a live record.
       Specifically, a record query of funk for rec's (xid,key) pair did
       not return rec.

   The record will cease to exist in that transaction and any of
   transaction's subsequently created descendants (again, assuming no
   subsequent insert of key).  This type of remove can be done on a
   published record (assuming the last published transaction is
   unfrozen). A tombstone is left in funk to track removals as they
   are published or cancelled.

   Any information in an erased record is lost.

   This is a reasonably fast O(1) and fortified against memory
   corruption. */

int
fd_funk_rec_remove( fd_funk_t *               funk,
                    fd_funk_txn_t *           txn,
                    fd_funk_rec_key_t const * key,
                    fd_funk_rec_t **          rec_out,
                    ulong                     erase_data );

/*
  fd_funk_rec_hard_remove completely removes the record from Funk,
  and leaves no tombstone behind.

  This is a dangerous API. An older version of the record in a
  parent transaction might be exposed. In other words, the record may
  appear to go backwards in time. We are effectively reverting an
  update. Any information in an removed record is lost.

  Always succeeds.
*/
void
fd_funk_rec_hard_remove( fd_funk_t *               funk,
                         fd_funk_txn_t *           txn,
                         fd_funk_rec_key_t const * key );

/* When a record is erased there is metadata stored in the five most
   significant bytes of record flags.  These are helpers to make setting
   and getting these values simple. The caller is responsible for doing
   a check on the flag of the record before using the value of the erase
   data. The 5 least significant bytes of the erase data parameter will
   be used and set into the erase flag. */

void
fd_funk_rec_set_erase_data( fd_funk_rec_t * rec, ulong erase_data );

ulong
fd_funk_rec_get_erase_data( fd_funk_rec_t const * rec );

/* Remove a list of tombstones from funk, thereby freeing up space in
   the main index. All the records must be removed and published
   beforehand. Reasons for failure include:

     FD_FUNK_ERR_INVAL - bad inputs (NULL funk, NULL rec, rec is
       obviously not from funk, etc)

     FD_FUNK_ERR_KEY - the record did not appear to be a removed record.
       Specifically, a record query of funk for rec's (xid,key) pair did
       not return rec. Also, the record was never published.
*/
int
fd_funk_rec_forget( fd_funk_t *      funk,
                    fd_funk_rec_t ** recs,
                    ulong            recs_cnt );

/* Iterator which walks all records in all transactions. Usage is:

  fd_funk_all_iter_t iter[1];
  for( fd_funk_all_iter_new( funk, iter ); !fd_funk_all_iter_done( iter ); fd_funk_all_iter_next( iter ) ) {
    fd_funk_rec_t const * rec = fd_funk_all_iter_ele_const( iter );
    ...
  }
*/

struct fd_funk_all_iter {
  fd_funk_rec_map_t      rec_map;
  ulong                  chain_cnt;
  ulong                  chain_idx;
  fd_funk_rec_map_iter_t rec_map_iter;
};

typedef struct fd_funk_all_iter fd_funk_all_iter_t;

void fd_funk_all_iter_new( fd_funk_t * funk, fd_funk_all_iter_t * iter );

int fd_funk_all_iter_done( fd_funk_all_iter_t * iter );

void fd_funk_all_iter_next( fd_funk_all_iter_t * iter );

fd_funk_rec_t const * fd_funk_all_iter_ele_const( fd_funk_all_iter_t * iter );

/* Misc */

#ifdef FD_FUNK_HANDHOLDING
/* fd_funk_rec_verify verifies the record map.  Returns FD_FUNK_SUCCESS
   if the record map appears intact and FD_FUNK_ERR_INVAL if not (logs
   details).  Meant to be called as part of fd_funk_verify.  As such, it
   assumes funk is non-NULL, fd_funk_{wksp,txn_map,rec_map} have been
   verified to work and the txn_map has been verified. */

int
fd_funk_rec_verify( fd_funk_t * funk );
#endif

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_funk_fd_funk_rec_h */
