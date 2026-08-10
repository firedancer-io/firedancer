#ifndef HEADER_fd_src_discof_backup_fd_backup_disk_h
#define HEADER_fd_src_discof_backup_fd_backup_disk_h

/* fd_backup_disk.h does streaming parsing of accdb disk partitions.
   Publishes discovered accounts (by disk offset) onto mcache/dcache. */

#include "fd_backup.h"
#include "fd_backup_accidx.h"
#include "fd_backup_visited.h"

/* FD_SNAPMK_PF_LEAD is how far ahead of the record cursor the parser
   prefetches disk bytes. */

#define FD_SNAPMK_PF_LEAD 4096UL

/* fd_snapmk_accparse_t does streaming zero-copy parsing of accdb
   partitions.  Ingests a stream of disk data (arbitrarily fragmented)
   and produces an account-aligned fragment stream. */

struct fd_snapmk_accparse {

  /* current input frag */
  uchar const * data;
  ulong         data_sz;
  ulong         src_gaddr;
  ulong         src_off;         /* accdb file offset of data */
  ulong         frag_base_gaddr; /* src_gaddr at start of current frag */
  uchar const * pf_cursor;       /* prefetch high-water mark within current frag */
  int           input_active;

  /* record being parsed */
  uint  meta_sz;      /* header bytes buffered so far, if torn */
  int   acc_active;
  uint  acc_off;      /* account data bytes consumed so far */
  uint  acc_sz;       /* account data byte count */
  uint  acc_snap_sz;  /* account byte count in snapshot format */
  uint  acc_idx;      /* index entry, UINT_MAX if not in the snapshot */
  uint  acc_keep;
  ulong acc_file_off; /* accdb file offset of the record header */

  /* output frag staged by fd_snapmk_accparse_publish, drained on its
     next call (the rest of the frag is derived from the fields above,
     which hold still until the record completes) */
  ulong pub_gaddr;
  uint  pub_sz;
  int   pub_pending;
  int   pub_som;
  int   pub_eom;

  fd_backup_accidx_t idx;
  visited_set_t *    visited_set;

  /* defrag buffer for torn disk partition data */
  union __attribute__((packed)) {
    uchar buf[ sizeof(fd_accdb_disk_meta_t) ];
    fd_accdb_disk_meta_t meta;
  };

  /* Whole records parsed out of the current frag, awaiting index
     lookup.  Staged one batch ahead of the batch being resolved so the
     chain head prefetches issued here land during that walk. */
  uint        ps_cnt;
  ulong       ps_chain_idx[ FD_BACKUP_DISK_PARA ];
  uint        ps_frag_off [ FD_BACKUP_DISK_PARA ];
  ulong       ps_file_off [ FD_BACKUP_DISK_PARA ];
};

typedef struct fd_snapmk_accparse fd_snapmk_accparse_t;

FD_PROTOTYPES_BEGIN

/* Implementation */

/* fd_snapmk_accparse_lookup resolves cnt parsed disk records against
   the accdb index.  chain_idx[ i ] is the acc_map chain that record i's
   address hashes to, file_off[ i ] its accdb file offset.  Sets
   acc_idx[ i ] to the index entry to copy into the snapshot, or
   UINT_MAX if the record should be skipped.

   A record is claimed by the index entry pointing at its exact file
   offset.  accdb file offsets are unique.  The record is skipped if
   no entry points at it (a superseded version still on disk), if the
   entry is unrooted or a tombstone, or if the account was already
   emitted from cache or from another partition. */

static inline void
fd_snapmk_accparse_lookup( fd_snapmk_accparse_t * parse,
                           ulong const *          chain_idx,
                           ulong const *          file_off,
                           uint *                 acc_idx,
                           ulong                  cnt ) {
  fd_backup_accidx_t *       idx      = &parse->idx;
  fd_accdb_accmeta_t const * acc_pool = idx->acc_pool;

  uint cur[ FD_BACKUP_DISK_PARA ]; /* chain node lane i sits on */

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *idx->epoch_slot ) = FD_VOLATILE_CONST( *idx->epoch );
  FD_HW_MFENCE();

  /* Chain heads were prefetched when this batch was prestaged, a full
     batch resolve ago. */
  for( ulong i=0UL; i<cnt; i++ ) {
    acc_idx[ i ] = UINT_MAX;
    cur    [ i ] = FD_VOLATILE_CONST( idx->acc_map[ chain_idx[ i ] ] );
  }

  int any;
  do {
    any = 0;
    for( ulong i=0UL; i<cnt; i++ ) {
      uint ele = cur[ i ];
      if( !fd_backup_accidx_valid( idx, ele ) ) continue; /* lane retired */

      fd_accdb_accmeta_t const * m = &acc_pool[ ele ];
      uint  next = FD_VOLATILE_CONST( m->map.next       );
      uint  gen  = FD_VOLATILE_CONST( m->key.generation );
      ulong off  = FD_VOLATILE_CONST( m->offset_fork    );
      ulong lam  = FD_VOLATILE_CONST( m->lamports       );

      int hit = fd_backup_accidx_rooted( idx, gen, lam )
              & ( ( off & FD_ACCDB_OFF_MASK )==file_off[ i ] );
      fd_uint_store_if( hit, &acc_idx[ i ], ele );

      /* Resolving hit and next in the same pass keeps the next node
         prefetch to the lanes that will actually use it. */
      int cont = (!hit) & fd_backup_accidx_valid( idx, next );
      cur[ i ] = fd_uint_if( cont, next, UINT_MAX );
      any     |= cont;
      __builtin_prefetch( &acc_pool[ next & (uint)(-cont) ], 0, 3 );
    }
  } while( any );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *idx->epoch_slot ) = ULONG_MAX;

  /* Claim each account for this snapshot, dropping the records that
     lost the claim to an earlier sighting. */
  for( ulong i=0UL; i<cnt; i++ ) {
    uint ele = acc_idx[ i ];
    if( FD_UNLIKELY( ele==UINT_MAX ) ) continue;
    if( FD_UNLIKELY( fd_backup_visited_test_and_set( parse->visited_set, (ulong)ele ) ) ) {
      acc_idx[ i ] = UINT_MAX;
    }
  }
}

/* fd_snapmk_accparse_keep returns 1 if the record whose header is in
   parse->meta should be copied into the snapshot being produced, 0
   otherwise, and sets parse->acc_idx to its index entry.  This is the
   fallback for records that straddle an input frag; whole records go
   through fd_snapmk_accparse_publish_batch below. */

static inline int
fd_snapmk_accparse_keep( fd_snapmk_accparse_t * parse ) {
  ulong chain_idx = fd_backup_accidx_chain( &parse->idx, parse->meta.pubkey );
  fd_snapmk_accparse_lookup( parse, &chain_idx, &parse->acc_file_off, &parse->acc_idx, 1UL );
  return parse->acc_idx!=UINT_MAX;
}

/* fd_snapmk_accparse_prestage consumes up to FD_BACKUP_DISK_PARA whole
   records from the current frag into parse->ps_*, and prefetches the
   index lines their lookup will need.  Does nothing unless the prestage
   is empty and the parser sits on a clean record boundary. */

static inline void
fd_snapmk_accparse_prestage( fd_snapmk_accparse_t * parse ) {
  if( FD_UNLIKELY( parse->ps_cnt ) ) return;
  if( FD_UNLIKELY( parse->pub_pending || parse->acc_active || parse->meta_sz ) ) return;

  ulong const meta_sz = sizeof(fd_accdb_disk_meta_t);

  fd_backup_accidx_t const * idx      = &parse->idx;
  uint const *               acc_map  = idx->acc_map;
  fd_accdb_accmeta_t const * acc_pool = idx->acc_pool;

  ulong * chain_idx = parse->ps_chain_idx;
  ulong   n         = 0UL;

  while( n<FD_BACKUP_DISK_PARA ) {
    if( parse->data_sz < meta_sz ) break; /* partial meta straddles frag end */

    /* Prefetch a fixed window ahead of the record cursor.  pf_cursor is
       a per-frag high-water mark, so each line is prefetched once no
       matter how the records fall across the window. */
    uchar const * pf_lim = parse->data + fd_ulong_min( parse->data_sz, FD_SNAPMK_PF_LEAD );
    uchar const * pf     = fd_ptr_if( parse->pf_cursor>parse->data, parse->pf_cursor, parse->data );
    for( ; pf<pf_lim; pf+=64UL ) __builtin_prefetch( pf, 0, 2 );
    parse->pf_cursor = pf_lim;

    fd_accdb_disk_meta_t const * dm = (fd_accdb_disk_meta_t const *)parse->data;
    ulong data_len = (ulong)FD_ACCDB_SIZE_DATA( dm->size );
    ulong rec      = meta_sz + data_len;
    if( parse->data_sz < rec ) break;     /* account data straddles frag end */

    chain_idx[ n ] = fd_backup_accidx_chain( idx, dm->pubkey );
    __builtin_prefetch( &acc_map[ chain_idx[ n ] ], 0, 3 );
    parse->ps_frag_off[ n ] = (uint)( parse->src_gaddr - parse->frag_base_gaddr );
    parse->ps_file_off[ n ] = parse->src_off;
    n++;

    parse->data      += rec;
    parse->data_sz   -= rec;
    parse->src_gaddr += rec;
    parse->src_off   += rec;
  }

  /* Head pass: acc_map lines were prefetched during the record walk
     above; prefetch the acc_pool[head] lines here. */
  for( ulong i=0UL; i<n; i++ ) {
    uint head = FD_VOLATILE_CONST( acc_map[ chain_idx[ i ] ] );
    int  live = fd_backup_accidx_valid( idx, head );
    __builtin_prefetch( &acc_pool[ head & (uint)(-live) ], 0, 3 );
  }

  parse->ps_cnt = (uint)n;
}

/* fd_snapmk_accparse_publish_batch fills batch with the next run of
   whole records from the current frag and returns how many.  Returns 0
   once the frag holds no more whole records, leaving any straddling
   remainder to fd_snapmk_accparse_publish.  Frag offsets in the batch
   are relative to parse->frag_base_gaddr. */

static inline ulong
fd_snapmk_accparse_publish_batch( fd_snapmk_accparse_t *       parse,
                                  fd_backup_disk_batch_msg_t * batch ) {
  fd_snapmk_accparse_prestage( parse );

  ulong n = (ulong)parse->ps_cnt;
  if( !n ) return 0UL;

  /* Move batch N out of the prestage buffer, then stage N+1 before
     resolving N so N+1's prefetches overlap N's chain walk. */
  ulong chain_idx[ FD_BACKUP_DISK_PARA ];
  ulong file_off [ FD_BACKUP_DISK_PARA ];
  memcpy( chain_idx,       parse->ps_chain_idx, n*sizeof(ulong)       );
  memcpy( file_off,        parse->ps_file_off,  n*sizeof(ulong)       );
  memcpy( batch->frag_off, parse->ps_frag_off,  n*sizeof(uint)        );
  parse->ps_cnt = 0U;

  fd_snapmk_accparse_prestage( parse );

  fd_snapmk_accparse_lookup( parse, chain_idx, file_off, batch->acc_idx, n );
  for( ulong i=n; i<FD_BACKUP_DISK_PARA; i++ ) batch->acc_idx[ i ] = UINT_MAX;

  return n;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_backup_disk_h */
