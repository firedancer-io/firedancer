#ifndef HEADER_fd_src_discof_backup_fd_backup_h
#define HEADER_fd_src_discof_backup_fd_backup_h

/* fd_backup.h provides the internal ABI for snapshot production IPC. */

#include "../restore/utils/fd_ssarchive.h"
#include "../../util/archive/fd_tar.h"

/* tango frag type in fd_frag_meta_t::ctl::orig
   Used by links snapmk_zp, snaprd_mk. */
#define FD_BACKUP_ORIG_START          1  /* mk->zp: start compressing */
#define FD_BACKUP_ORIG_ACC_CACHE      2  /* mk->zp: pointers to cached account */
#define FD_BACKUP_ORIG_ACC_DISK       3  /* mk->zp: disk offset to cold account */
#define FD_BACKUP_ORIG_FLUSH          4  /* mk->zp: flush compress buffer */
#define FD_BACKUP_ORIG_DONE           5  /* mk->zp: stop compressing; mk->replay: free bank_idx */
#define FD_BACKUP_ORIG_ACC_DISK_BATCH 6  /* mk->zp: batch of cold accounts within one rd frag */
#define FD_BACKUP_ORIG_DISK_FRAG      7  /* rd->mk: accdb file frag */
#define FD_BACKUP_ORIG_ACC_DELTA      8  /* mk->zp: address of account */

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
/* levels 4-15 are compiled out of libfd_zstd (third_party/zstd/Local.mk) */
FD_STATIC_ASSERT( FD_BACKUP_ZSTD_LEVEL<=3 || FD_BACKUP_ZSTD_LEVEL>=16, zstd_level );

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
#define FD_SNAP_FD(     i ) (FD_SNAP_FD_BASE                     +(int)(i))
#define FD_SNAP_DIO_FD( i ) (FD_SNAP_FD_BASE+   (int)FD_SNAP_MAX +(int)(i))
#define FD_SNAP_RO_FD(  i ) (FD_SNAP_FD_BASE+(2*(int)FD_SNAP_MAX)+(int)(i))

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
  ulong  base_slot; /* full snapshot slot for an incremental, ULONG_MAX otherwise */
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
  uint        acc_idx [ FD_BACKUP_DISK_PARA ]; /* UINT_MAX is sentinel */
  uint        frag_off[ FD_BACKUP_DISK_PARA ];
};
typedef struct fd_backup_disk_batch_msg fd_backup_disk_batch_msg_t;

/* fd_backup_delta_msg_t is a batch of incremental snapshot accounts by
   address. */

struct fd_backup_delta_msg {
  uint        cnt;
  fd_pubkey_t pubkey[ FD_BACKUP_CACHE_PARA ];
};

typedef struct fd_backup_delta_msg fd_backup_delta_msg_t;

/* fd_backup_frag_t is only used to determine MTU of link */

union fd_backup_frag {
  fd_backup_start_msg_t      start;
  fd_backup_cache_msg_t      cache;
  fd_backup_disk_msg_t       disk;
  fd_backup_disk_batch_msg_t disk_batch;
  fd_backup_delta_msg_t      delta;
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

/* fd_backup_appendvec_slot returns the slot in the tar entry name of
   the idx-th appendvec of a snapshot archive (idx starts at 0).

   Agave requires one appendvec per slot and keys storages by slot
   alone.  When the same account appears in two appendvecs the higher
   slot wins.  The Firedancer producer never emits an account twice
   within an archive, so any distinct slots at or below the snapshot
   slot are valid for a full snapshot.  For an incremental snapshot
   every slot must exceed the base slot so its updates and tombstones
   override the full snapshot's copies.  So we start at the snapshot
   slot and count down.

   base_slot is ULONG_MAX for a full snapshot.  Returns ULONG_MAX if
   idx does not fit the archive's slot window, which is
   [0, snapshot_slot] for a full snapshot and
   (base_slot, snapshot_slot] for an incremental snapshot. */

FD_FN_CONST static inline ulong
fd_backup_appendvec_slot( ulong snapshot_slot,
                          ulong base_slot,
                          ulong idx ) {
  ulong window;
  if( base_slot==ULONG_MAX ) window = snapshot_slot+1UL; /* full */
  else                       window = snapshot_slot>base_slot ? snapshot_slot-base_slot : 0UL;
  if( FD_UNLIKELY( idx>=window ) ) return ULONG_MAX;
  return snapshot_slot-idx;
}

/* fd_backup_appendvec_name writes the tar entry name of an appendvec
   with the given slot to name ("accounts/<slot>.0").  The id after
   the dot only has to be unique within a slot, and Agave replaces it
   at load time anyway, so it is always 0.  Returns name. */

static inline char *
fd_backup_appendvec_name( char  name[ static FD_TAR_NAME_SZ ],
                          ulong slot ) {
  char * p = fd_cstr_init( name );
  p = fd_cstr_append_cstr( p, "accounts/" );
  p = fd_cstr_append_ulong_as_text( p, 0, 0, slot, fd_ulong_base10_dig_cnt( slot ) );
  p = fd_cstr_append_cstr( p, ".0" );
  fd_cstr_fini( p );
  return name;
}

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
