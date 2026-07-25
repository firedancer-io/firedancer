#ifndef HEADER_fd_src_discof_backup_fd_backup_h
#define HEADER_fd_src_discof_backup_fd_backup_h

/* fd_backup.h produces Solana snapshots from Firedancer state. */

#include "../restore/utils/fd_ssarchive.h"
#include "../../util/archive/fd_tar.h"

/* tango frag type in fd_frag_meta_t::ctl::orig */
#define FD_BACKUP_ORIG_START          1  /* mk->zp: start compressing */
#define FD_BACKUP_ORIG_ACC_CACHE      2  /* mk->zp: pointers to cached account */
#define FD_BACKUP_ORIG_ACC_DISK       3  /* mk->zp: disk offset to cold account */
#define FD_BACKUP_ORIG_FLUSH          4  /* mk->zp: flush compress buffer */
#define FD_BACKUP_ORIG_DONE           5  /* mk->zp: stop compressing; mk->replay: free bank_idx */
#define FD_BACKUP_ORIG_ACC_DISK_BATCH 6  /* mk->zp: batch of cold accounts within one rd frag */
#define FD_BACKUP_ORIG_DISK_START     7  /* mk->rd: start reading from disk */
#define FD_BACKUP_ORIG_DISK_FRAG      8  /* rd->mk: accdb file frag */

/* FD_BACKUP_CACHE_PARA controls the batch size of ultra-sparse random
   index lookups from acc_map.  Tunes memory-level parallelism settings
   when doing DRAM gather. */

#define FD_BACKUP_CACHE_PARA 128
#define FD_BACKUP_DISK_PARA  128

/* FD_BACKUP_RD_MTU is the max frag size on a snaprd_out link. */

#define FD_BACKUP_RD_MTU 262144UL

/* FD_BACKUP_ZSTD_LEVEL is the Zstandard compression level of snapshots
   produced by Firedancer. */

#define FD_BACKUP_ZSTD_LEVEL 1

/* FD_SNAP_MAX bounds the number of managed snapshot files
   (max_full_snapshots_to_keep+max_incremental_snapshots_to_keep, plus
   up to two scratch slots for a snapshot class that is downloaded but
   not retained). */

#define FD_SNAP_MAX (2U*(uint)FD_SSARCHIVE_MAX_ENTRIES+2U)

/* Well-known snapshot file descriptors

   Firedancer's strict sandbox bans opening/creating new files via
   open(2).  Instead, Firedancer opens a fixed number of existing
   snapshots and creates placeholder files.  Each file is eventually
   recycled by truncating and renaming it. */

#define FD_SNAP_FD_BASE (200000)
#define FD_SNAP_FD(     i ) (FD_SNAP_FD_BASE                 +(int)(i))
#define FD_SNAP_DIO_FD( i ) (FD_SNAP_FD_BASE+(int)FD_SNAP_MAX+(int)(i))

/* fd_backup_inode_t annotates a snapshot file descriptor. */

struct fd_backup_inode {
  char  name[ FD_SNAP_NAME_MAX ];
  ulong full_slot; /* ULONG_MAX if placeholder */
  ulong incr_slot; /* ULONG_MAX if placeholder or full snapshot */
};

typedef struct fd_backup_inode fd_backup_inode_t;

/* fd_backup_start_msg_t (FD_BACKUP_ORIG_START) is the snapshot pipeline
   start signal. */

struct fd_backup_start_msg {
  ulong  slot;      /* slot number */
  uint   snap_idx;  /* identifies file descriptor */
  ushort fork_id;   /* accdb fork ID */
};
typedef struct fd_backup_start_msg fd_backup_start_msg_t;

/* fd_backup_cache_msg_t (FD_BACKUP_ORIG_ACC_CACHE) is a batch of cached
   account compression jobs. */

struct fd_backup_cache_msg {
  uint        acc_idx[ FD_BACKUP_CACHE_PARA ]; /* UINT_MAX is sentinel */
  fd_pubkey_t pubkey [ FD_BACKUP_CACHE_PARA ];
};
typedef struct fd_backup_cache_msg fd_backup_cache_msg_t;

/* fd_backup_disk_msg_t (FD_BACKUP_ORIG_ACC_DISK) is a compression job
   for an account that was read from disk (possibly fragmented). */

struct fd_backup_disk_msg {
  fd_pubkey_t pubkey;
  fd_pubkey_t owner;
  uint        size;
  uint        acc_idx;
  uint        snap_sz;
  uint        data_sz;
};
typedef struct fd_backup_disk_msg fd_backup_disk_msg_t;

/* fd_backup_disk_batch_msg_t (FD_BACKUP_ORIG_ACC_DISK_BATCH) is a batch
   compression jobs for multiple disk accounts that were read into a
   contiguous buffer (fast path). */

struct fd_backup_disk_batch_msg {
  fd_pubkey_t pubkey  [ FD_BACKUP_DISK_PARA ];
  uint        acc_idx [ FD_BACKUP_DISK_PARA ]; /* UINT_MAX is sentinel */
  uint        frag_off[ FD_BACKUP_DISK_PARA ];
};
typedef struct fd_backup_disk_batch_msg fd_backup_disk_batch_msg_t;

/* fd_backup_frag_t is only used to determine MTU of link */

union fd_backup_frag {
  fd_backup_start_msg_t      start;
  fd_backup_cache_msg_t      cache;
  fd_backup_disk_msg_t       disk;
  fd_backup_disk_batch_msg_t disk_batch;
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
    .version  = { ' ','\0' },
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
    .version  = { ' ','\0' },
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
