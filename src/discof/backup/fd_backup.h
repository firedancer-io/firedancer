#ifndef HEADER_fd_src_discof_backup_fd_backup_h
#define HEADER_fd_src_discof_backup_fd_backup_h

/* fd_backup.h produces Solana snapshots from Firedancer state.

   fd_backup_cache snapshots accounts from in-memory cache.
   fd_backup_accdb snapshots accounts from disk. */

#include "../../flamenco/fd_flamenco_base.h"
#include "../../util/archive/fd_tar.h"

#define FD_BACKUP_ORIG_START     1
#define FD_BACKUP_ORIG_ACC_CACHE 2
#define FD_BACKUP_ORIG_FLUSH     3
#define FD_BACKUP_ORIG_RESET     4
#define FD_BACKUP_ORIG_DONE      5

#define FD_BACKUP_CACHE_PARA 128
#define FD_BACKUP_NAME_MAX   128

union fd_backup_frag {

  /* start new snapshot at this path */
  struct {
    ushort name_len;
    char   name[ FD_BACKUP_NAME_MAX ];
  } start;

  /* a batch of accounts that are currently rooted, and have recently
     been in the cache (but could have been evicted to disk).
     sparse, acc_idx[i] may be UINT_MAX (sentinel) */
  struct {
    uint        acc_idx[ FD_BACKUP_CACHE_PARA ];
    fd_pubkey_t pubkey [ FD_BACKUP_CACHE_PARA ];
  } acc_cache;

  /* a batch of accounts on disk
     sparse, offset[i] may be ULONG_MAX (sentinel) */
  struct {
    ulong offset[ FD_BACKUP_CACHE_PARA ];
  } acc_disk;

};

typedef union fd_backup_frag fd_backup_frag_t;

/* snap_acc_hdr_t is a snapshot-format account header. */

union __attribute__((packed)) snap_acc_hdr {
  struct __attribute__((packed)) {
    /* 0x00 */ ulong       slot;
    /* 0x08 */ ulong       data_len;
    /* 0x10 */ fd_pubkey_t pubkey;
    /* 0x30 */ ulong       lamports;
    /* 0x38 */ ulong       rent_epoch;
    /* 0x40 */ fd_pubkey_t owner;
    /* 0x60 */ uchar       executable;
    /* 0x61 */ uchar       padding[7];
    /* 0x68 */ fd_hash_t   hash;
    /* 0x88 */
  };
  uchar raw[ 0x88 ];
};
typedef union snap_acc_hdr snap_acc_hdr_t;

FD_PROTOTYPES_BEGIN

/* Utils */

FD_FN_UNUSED static fd_tar_meta_t *
fd_backup_tar_file_hdr( fd_tar_meta_t * tar_meta,
                        ulong           sz ) {
  *tar_meta = (fd_tar_meta_t){
    .magic    = { 'u','s','t','a','r',' ' },
    .mode     = "644",
    .uid      = "0",
    .gid      = "0",
    .typeflag = FD_TAR_TYPE_REGULAR,
    .chksum   = { ' ',' ',' ',' ',' ',' ',' ',' ' }
  };
  (void)fd_tar_meta_set_size( tar_meta, sz );
  return tar_meta;
}

FD_FN_UNUSED static fd_tar_meta_t *
fd_backup_tar_dir_hdr( fd_tar_meta_t * tar_meta ) {
  *tar_meta = (fd_tar_meta_t){
    .magic    = { 'u','s','t','a','r',' ' },
    .mode     = "755",
    .uid      = "0",
    .gid      = "0",
    .typeflag = FD_TAR_TYPE_DIR,
    .chksum   = { ' ',' ',' ',' ',' ',' ',' ',' ' }
  };
  (void)fd_tar_meta_set_size( tar_meta, 0UL );
  return tar_meta;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_backup_h */
