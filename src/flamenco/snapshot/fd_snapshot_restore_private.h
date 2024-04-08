#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_restore_private_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_restore_private_h

#include "fd_snapshot_restore.h"

/* fd_valloc_limit_t wraps a heap allocator and keeps track of
   allocation quota.  Once exceeded, quota is set to 0UL and all
   allocation attempts return NULL.  frees are always forwarded to the
   underlying valloc. */

struct fd_valloc_limit {
  fd_valloc_t valloc;
  ulong       quota;
  ulong       quota_orig;
};

typedef struct fd_valloc_limit fd_valloc_limit_t;

/* Accounts are loaded from a snapshot via "account vec" files, each
   containing multiple accounts.  However, external information is
   required to determine the size of these files.  This information is
   stored in the "manifest" file, which is loaded at the beginning of
   the snapshot.

   The below map serves to store the file size information. */

struct fd_snapshot_accv_key {
  ulong slot;
  ulong id;
};

typedef struct fd_snapshot_accv_key fd_snapshot_accv_key_t;

static const fd_snapshot_accv_key_t
fd_snapshot_accv_key_null = { 0UL, 0UL };

static inline ulong
fd_snapshot_accv_key_hash( fd_snapshot_accv_key_t key ) {
  return fd_hash( 0x39c49607bf16463aUL, &key, sizeof(fd_snapshot_accv_key_t) );
}

struct fd_snapshot_accv_map {
  fd_snapshot_accv_key_t key;
  ulong                  sz;
  ulong                  hash;  /* use uint or ulong hash? */
};

typedef struct fd_snapshot_accv_map fd_snapshot_accv_map_t;

#define MAP_NAME              fd_snapshot_accv_map
#define MAP_T                 fd_snapshot_accv_map_t
#define MAP_LG_SLOT_CNT       23  /* 8.39 million */
#define MAP_KEY_T             fd_snapshot_accv_key_t
#define MAP_KEY_NULL          fd_snapshot_accv_key_null
#define MAP_KEY_INVAL(k)      ( ((k).slot==0UL) & ((k).id==0UL) )
#define MAP_KEY_EQUAL(k0,k1)  ( ((k0).slot==(k1).slot) & ((k0).id==(k1).id) )
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_HASH_T            ulong
#define MAP_KEY_HASH(k0)      fd_snapshot_accv_key_hash(k0)
#include "../../util/tmpl/fd_map.c"

/* Main snapshot restore **********************************************/

struct fd_snapshot_restore {
  fd_acc_mgr_t *    acc_mgr;
  fd_funk_txn_t *   funk_txn;
  fd_valloc_t       valloc;

  ulong slot;  /* Slot number the snapshot was taken at */

  uchar state;
  uchar manifest_done : 1;
  uchar failed        : 1;

  /* Buffer params.  This buffer is used to gather file content into
     a contiguous byte array.  Currently in use for the manifest and the
     account headers.  (Account data does not use this buffer) */

  uchar * buf;      /* points to first byte of buffer */
  ulong   buf_ctr;  /* number of bytes allocated in buffer */
  ulong   buf_sz;   /* target buffer size (buf_ctr<buf_sz implies incomplete read) */
  ulong   buf_cap;  /* byte capacity of buffer */

  /* Account vec params.  Sadly, Solana Labs encodes account vecs with
     garbage at the end of the file.  The actual account vec sz can be
     smaller.  In this case, we have to stop reading account data early
     and skip the garbage/padding. */

  ulong   accv_slot;  /* account vec slot */
  ulong   accv_id;    /* account vec index */
  ulong   accv_sz;    /* account vec size */
  fd_snapshot_accv_map_t * accv_map;

  /* Account size.  Used when reading account data. */

  ulong   acc_sz;    /* acc bytes pending write */
  uchar * acc_data;  /* pointer into funk acc data pending write */
  ulong   acc_pad;   /* padding size at end of account */

  /* Consumer callback */

  fd_snapshot_restore_cb_manifest_fn_t cb_manifest;
  void *                               cb_manifest_ctx;
};

/* STATE_{...} are the state IDs that control file processing in the
   snapshot streaming state machine. */

#define STATE_IGNORE            ((uchar)0)  /* ignore file content */
#define STATE_READ_MANIFEST     ((uchar)1)  /* reading manifest (buffered) */
#define STATE_READ_ACCOUNT_HDR  ((uchar)2)  /* reading account hdr (buffered) */
#define STATE_READ_ACCOUNT_DATA ((uchar)3)  /* reading account data (direct copy into funk) */
#define STATE_DONE              ((uchar)4)  /* expect no more data */

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_restore_private_h */
