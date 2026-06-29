#ifndef HEADER_fd_src_discof_backup_fd_backup_h
#define HEADER_fd_src_discof_backup_fd_backup_h

/* fd_backup.h produces Solana snapshots from Firedancer state.

   fd_backup_cache snapshots accounts from in-memory cache.
   fd_backup_accdb snapshots accounts from disk. */

#include "../../flamenco/fd_flamenco_base.h"
#include "../../util/archive/fd_tar.h"

/* tango frag type in fd_frag_meta_t::ctl::orig */
#define FD_BACKUP_ORIG_START        1  /* mk->zp: start compressing */
#define FD_BACKUP_ORIG_ACC_CACHE    2  /* mk->zp: pointers to cached account */
#define FD_BACKUP_ORIG_ACC_DISK     3  /* mk->zp: disk offset to cold account */
#define FD_BACKUP_ORIG_FLUSH        4  /* mk->zp: flush compress buffer */
#define FD_BACKUP_ORIG_DONE         5  /* mk->zp: stop compressing */
#define FD_BACKUP_ORIG_DISK_START  16  /* mk->rd: start reading from disk */
#define FD_BACKUP_ORIG_DISK_FRAG   17  /* rd->mk: accdb file frag */

/* snapmk lifecycle states */
#define SNAPMK_STATE_IDLE             0 /* clean, waiting for job */
#define SNAPMK_STATE_START            1
#define SNAPMK_STATE_TAR_HEADERS      2
#define SNAPMK_STATE_MANIFEST         3 /* writing manifest */
#define SNAPMK_STATE_ACCOUNTS_CACHE   4 /* writing cached accounts */
#define SNAPMK_STATE_ACCOUNTS_FLUSH1  5 /* flushing cached accounts */
#define SNAPMK_STATE_ACCOUNTS_DISK    6 /* writing on-disk accounts */
#define SNAPMK_STATE_ACCOUNTS_FLUSH2  7 /* flushing on-disk accounts */
#define SNAPMK_STATE_ACCOUNTS_DRAIN   8 /* wait for flush to complete */
#define SNAPMK_STATE_STATUS_CACHE     9 /* writing status cache */
#define SNAPMK_STATE_EOF_MARKER      10 /* writing tar EOF marker */
#define SNAPMK_STATE_DONE            11 /* done, notify replay tile */
#define SNAPMK_STATE_FAIL            12 /* error state, doing cleanup */

/* FD_BACKUP_CACHE_PARA controls the batch size of ultra-sparse random
   index lookups from acc_map.  Tunes memory-level parallelism settings
   when doing DRAM gather. */
#define FD_BACKUP_CACHE_PARA 128

/* FD_BACKUP_NAME_MAX is the max cstr size (null included) of a snapshot
   file name. */
#define FD_BACKUP_NAME_MAX 128

/* FD_BACKUP_RD_MTU is the max frag size on an snaprd_out link.
   The snaprd_out::sz field is 1-based to support this.
   (It is not possible to publish an empty-sized frag) */
#define FD_BACKUP_RD_MTU 65536UL

struct fd_backup_start_msg {
  ushort name_len;
  char   name[ FD_BACKUP_NAME_MAX ];
};
typedef struct fd_backup_start_msg fd_backup_start_msg_t;

struct fd_backup_cache_msg {
  uint        acc_idx[ FD_BACKUP_CACHE_PARA ]; /* UINT_MAX is sentinel */
  fd_pubkey_t pubkey [ FD_BACKUP_CACHE_PARA ];
};
typedef struct fd_backup_cache_msg fd_backup_cache_msg_t;

struct fd_backup_disk_msg {
  fd_pubkey_t pubkey;
  fd_pubkey_t owner;
  uint        size;
  uint        acc_idx;
  uint        snap_sz;
  uint        data_sz;
};
typedef struct fd_backup_disk_msg fd_backup_disk_msg_t;

/* Only used to determine MTU of link */
union fd_backup_frag {
  fd_backup_start_msg_t start;
  fd_backup_cache_msg_t acc_cache;
  fd_backup_disk_msg_t  acc_disk;
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
