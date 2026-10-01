#include "fd_dragon_buf.h"

#define FD_DRAGON_BUF_MAGIC (0xf17eda2547d2a601UL) /* firedancer dragon buf */

/* Entries start at a chunk boundary, so that the chunk index of an
   mcache line addresses one exactly, the way it does on any link. */

#define FD_DRAGON_BUF_ENTRY_ALIGN (FD_CHUNK_SZ)

/* buf_dedup_slot_t is one slot of the deduplication table: the entry
   that currently wins an account of the bank being served.  gen is
   the pass that wrote the slot, so the table is never cleared between
   banks. */

struct buf_dedup_slot {
  ulong gen;
  ulong seq;
};

typedef struct buf_dedup_slot buf_dedup_slot_t;

struct fd_dragon_buf {
  ulong magic;

  ulong bank_max;
  ulong depth;
  ulong data_sz;

  fd_frag_meta_t * mcache;
  uchar *          dcache;
  void *           base;

  ulong seq;        /* sequence number of the next entry */
  ulong pos;        /* byte position of the next entry; pos%data_sz is its offset */

  ulong bank_cnt;
  ulong entry_cnt;  /* entries of the banks the table holds */
  ulong oldest_pos; /* byte position of the oldest of those entries */
  ulong last_idx;   /* the bank entry looked up last */
  ulong gen;        /* deduplication pass */

  fd_dragon_buf_bank_t * bank;  /* bank_max entries */
  buf_dedup_slot_t *     dedup; /* depth entries */

  fd_dragon_buf_metrics_t metrics;
};

FD_FN_CONST ulong
fd_dragon_buf_align( void ) {
  return FD_DRAGON_BUF_ALIGN;
}

ulong
fd_dragon_buf_footprint( fd_dragon_buf_params_t const * params ) {
  if( FD_UNLIKELY( !params->bank_max || !params->depth || !fd_ulong_is_pow2( params->depth ) ) ) return 0UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_DRAGON_BUF_ALIGN,           sizeof(fd_dragon_buf_t)                      );
  l = FD_LAYOUT_APPEND( l, alignof(fd_dragon_buf_bank_t), params->bank_max*sizeof(fd_dragon_buf_bank_t) );
  l = FD_LAYOUT_APPEND( l, alignof(buf_dedup_slot_t),     params->depth*sizeof(buf_dedup_slot_t)       );
  return FD_LAYOUT_FINI( l, FD_DRAGON_BUF_ALIGN );
}

void *
fd_dragon_buf_new( void *                         mem,
                   fd_dragon_buf_params_t const * params ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_DRAGON_BUF_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_dragon_buf_footprint( params ) ) ) {
    FD_LOG_WARNING(( "invalid fd_dragon_buf params" ));
    return NULL;
  }
  if( FD_UNLIKELY( !params->mcache || !params->dcache || !params->base ) ) {
    FD_LOG_WARNING(( "NULL ring" ));
    return NULL;
  }
  if( FD_UNLIKELY( fd_mcache_depth( params->mcache )!=params->depth ) ) {
    FD_LOG_WARNING(( "mcache depth %lu, expected %lu", fd_mcache_depth( params->mcache ), params->depth ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)params->dcache, FD_DRAGON_BUF_ENTRY_ALIGN ) ||
                   (ulong)params->dcache<(ulong)params->base ) ) {
    FD_LOG_WARNING(( "misaligned dcache" ));
    return NULL;
  }
  ulong data_sz = fd_dcache_data_sz( params->dcache );
  if( FD_UNLIKELY( data_sz<2UL*FD_DRAGON_BUF_ENTRY_ALIGN ) ) {
    FD_LOG_WARNING(( "dcache too small" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_dragon_buf_t * buf   = FD_SCRATCH_ALLOC_APPEND( l, FD_DRAGON_BUF_ALIGN,           sizeof(fd_dragon_buf_t)                       );
  void *            bank  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_dragon_buf_bank_t), params->bank_max*sizeof(fd_dragon_buf_bank_t) );
  void *            dedup = FD_SCRATCH_ALLOC_APPEND( l, alignof(buf_dedup_slot_t),     params->depth*sizeof(buf_dedup_slot_t)        );
  FD_SCRATCH_ALLOC_FINI( l, FD_DRAGON_BUF_ALIGN );

  fd_memset( buf,   0, sizeof(fd_dragon_buf_t) );
  fd_memset( dedup, 0, params->depth*sizeof(buf_dedup_slot_t) );

  buf->bank_max = params->bank_max;
  buf->depth    = params->depth;
  buf->data_sz  = data_sz;
  buf->mcache   = params->mcache;
  buf->dcache   = params->dcache;
  buf->base     = params->base;
  buf->bank     = bank;
  buf->dedup    = dedup;
  buf->last_idx = ULONG_MAX;

  /* The ring's lines say nothing until an entry is written to them,
     so no stale sequence number can pass for one of ours. */
  for( ulong i=0UL; i<params->depth; i++ ) buf->mcache[ i ].seq = ULONG_MAX;
  for( ulong i=0UL; i<params->bank_max; i++ ) buf->bank[ i ].bank_seq = ULONG_MAX;

  FD_COMPILER_MFENCE();
  buf->magic = FD_DRAGON_BUF_MAGIC;
  FD_COMPILER_MFENCE();
  return mem;
}

fd_dragon_buf_t *
fd_dragon_buf_join( void * mem ) {
  fd_dragon_buf_t * buf = mem;
  if( FD_UNLIKELY( !buf ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( buf->magic!=FD_DRAGON_BUF_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return buf;
}

/* Banks **************************************************************/

fd_dragon_buf_bank_t *
fd_dragon_buf_bank( fd_dragon_buf_t * buf,
                    ulong             bank_seq ) {
  if( FD_UNLIKELY( bank_seq==ULONG_MAX ) ) return NULL;

  /* The records of one bank arrive together, so the entry looked up
     last is almost always the one wanted. */
  if( FD_LIKELY( buf->last_idx<buf->bank_max &&
                 buf->bank[ buf->last_idx ].bank_seq==bank_seq ) ) return buf->bank + buf->last_idx;

  for( ulong i=0UL; i<buf->bank_max; i++ ) {
    if( buf->bank[ i ].bank_seq!=bank_seq ) continue;
    buf->last_idx = i;
    return buf->bank + i;
  }
  return NULL;
}

fd_dragon_buf_bank_t *
fd_dragon_buf_bank_open( fd_dragon_buf_t * buf,
                         ulong             bank_seq,
                         ulong             slot ) {
  fd_dragon_buf_bank_t * bank = fd_dragon_buf_bank( buf, bank_seq );
  if( FD_LIKELY( bank ) ) return bank;
  if( FD_UNLIKELY( bank_seq==ULONG_MAX ) ) return NULL;

  for( ulong i=0UL; i<buf->bank_max; i++ ) {
    if( buf->bank[ i ].bank_seq!=ULONG_MAX ) continue;
    bank = buf->bank + i;
    fd_memset( bank, 0, sizeof(fd_dragon_buf_bank_t) );
    bank->bank_seq  = bank_seq;
    bank->slot      = slot;
    bank->first_seq = ULONG_MAX;
    bank->last_seq  = ULONG_MAX;
    buf->bank_cnt++;
    buf->last_idx = i;
    buf->metrics.bank_open_cnt++;
    return bank;
  }

  buf->metrics.bank_full_cnt++;
  return NULL;
}

/* buf_oldest_refresh recomputes the position of the oldest entry the
   table still names, after a bank left it. */

static void
buf_oldest_refresh( fd_dragon_buf_t * buf ) {
  ulong oldest = ULONG_MAX;
  for( ulong i=0UL; i<buf->bank_max; i++ ) {
    fd_dragon_buf_bank_t const * bank = buf->bank + i;
    if( bank->bank_seq==ULONG_MAX || bank->first_seq==ULONG_MAX ) continue;
    oldest = fd_ulong_min( oldest, bank->first_pos );
  }
  buf->oldest_pos = oldest==ULONG_MAX ? buf->pos : oldest;
}

void
fd_dragon_buf_bank_drop( fd_dragon_buf_t *      buf,
                         fd_dragon_buf_bank_t * bank ) {
  buf->entry_cnt -= bank->entry_cnt;
  bank->bank_seq  = ULONG_MAX;
  buf->bank_cnt--;
  buf->metrics.bank_drop_cnt++;
  if( bank->first_seq!=ULONG_MAX ) buf_oldest_refresh( buf );
}

int
fd_dragon_buf_bank_live( fd_dragon_buf_t *      buf,
                         fd_dragon_buf_bank_t * bank ) {
  if( FD_LIKELY( bank->first_seq==ULONG_MAX ) ) return 1;

  /* The first entry is the oldest of the bank's, so it is the one the
     ring comes round to first: it is intact while fewer than depth
     entries and fewer than data_sz bytes have been written since it,
     the second counted with the bytes a wrap skips. */
  int live = ( buf->seq-bank->first_seq<=buf->depth   ) &
             ( buf->pos-bank->first_pos<=buf->data_sz );
  if( FD_LIKELY( live ) ) return 1;

  if( FD_LIKELY( !bank->incomplete ) ) {
    bank->incomplete = 1;
    buf->metrics.overrun_cnt++;
  }
  return 0;
}

fd_dragon_buf_bank_t *
fd_dragon_buf_bank_iter( fd_dragon_buf_t * buf,
                         ulong *           idx ) {
  for( ulong i=*idx; i<buf->bank_max; i++ ) {
    if( buf->bank[ i ].bank_seq==ULONG_MAX ) continue;
    *idx = i+1UL;
    return buf->bank + i;
  }
  *idx = buf->bank_max;
  return NULL;
}

/* Entries ************************************************************/

fd_dragon_buf_hdr_t *
fd_dragon_buf_push( fd_dragon_buf_t *      buf,
                    fd_dragon_buf_bank_t * bank,
                    uint                   kind,
                    ulong                  sz ) {
  ulong need = fd_ulong_align_up( sz, FD_DRAGON_BUF_ENTRY_ALIGN );
  if( FD_UNLIKELY( need<sz || need>buf->data_sz ) ) {
    buf->metrics.push_fail_cnt++;
    return NULL;
  }

  /* An entry never straddles the end of the ring: the tail that is too
     short for it is skipped, and counted as written so that positions
     keep pace with offsets. */
  ulong off = buf->pos % buf->data_sz;
  if( FD_UNLIKELY( off+need>buf->data_sz ) ) {
    buf->pos += buf->data_sz-off;
    off       = 0UL;
  }

  ulong                 seq = buf->seq;
  ulong                 pos = buf->pos;
  fd_dragon_buf_hdr_t * hdr = (fd_dragon_buf_hdr_t *)( buf->dcache + off );

  fd_frag_meta_t * line = buf->mcache + ( seq & ( buf->depth-1UL ) );
  line->seq    = seq;
  line->sig    = bank->bank_seq;
  line->chunk  = (uint)fd_laddr_to_chunk( buf->base, hdr );
  line->sz     = 0U;
  line->ctl    = 0U;
  line->tsorig = 0U;
  line->tspub  = 0U;

  hdr->seq        = seq;
  hdr->bank_seq   = bank->bank_seq;
  hdr->slot       = bank->slot;
  hdr->sz         = need;
  hdr->mask       = 0UL;
  hdr->status_mask= 0UL;
  hdr->block_mask = 0UL;
  hdr->push_mask  = 0UL;
  hdr->kind       = kind;
  hdr->name_cnt   = 0U;
  hdr->superseded = 0U;
  hdr->pad        = 0U;

  if( FD_UNLIKELY( bank->first_seq==ULONG_MAX ) ) {
    bank->first_seq = seq;
    bank->first_pos = pos;
    if( FD_UNLIKELY( !buf->entry_cnt ) ) buf->oldest_pos = pos;
  }
  bank->last_seq = seq;
  bank->entry_cnt++;
  if( kind==FD_DRAGON_BUF_TXN ) bank->txn_cnt++;
  else                          bank->acct_cnt++;

  buf->seq  = seq+1UL;
  buf->pos  = pos+need;
  buf->entry_cnt++;

  buf->metrics.push_cnt[ kind==FD_DRAGON_BUF_TXN ? 0 : 1 ]++;
  buf->metrics.push_byte_cnt += need;
  buf->metrics.byte_hi  = fd_ulong_max( buf->metrics.byte_hi,  buf->pos-buf->oldest_pos );
  buf->metrics.entry_hi = fd_ulong_max( buf->metrics.entry_hi, buf->entry_cnt          );
  return hdr;
}

fd_dragon_buf_hdr_t *
fd_dragon_buf_entry( fd_dragon_buf_t *            buf,
                     fd_dragon_buf_bank_t const * bank,
                     ulong                        seq ) {
  if( FD_UNLIKELY( bank->first_seq==ULONG_MAX || seq<bank->first_seq || seq>bank->last_seq ) ) return NULL;
  fd_frag_meta_t const * line = buf->mcache + ( seq & ( buf->depth-1UL ) );
  if( FD_UNLIKELY( line->seq!=seq || line->sig!=bank->bank_seq ) ) return NULL;
  return fd_chunk_to_laddr( buf->base, line->chunk );
}

static inline ulong
buf_pubkey_hash( uchar const * pubkey ) {
  return fd_ulong_hash( FD_LOAD( ulong, pubkey ) ^ FD_LOAD( ulong, pubkey+8UL ) );
}

ulong
fd_dragon_buf_dedup( fd_dragon_buf_t *            buf,
                     fd_dragon_buf_bank_t const * bank ) {
  if( FD_UNLIKELY( bank->first_seq==ULONG_MAX || !bank->acct_cnt ) ) return 0UL;

  /* A pass is told apart from every earlier one by its generation, so
     the table is clean without being cleared.  The generation that
     wraps to the value the slots were zeroed with clears it once. */
  buf->gen++;
  if( FD_UNLIKELY( !buf->gen ) ) {
    fd_memset( buf->dedup, 0, buf->depth*sizeof(buf_dedup_slot_t) );
    buf->gen = 1UL;
  }
  ulong gen  = buf->gen;
  ulong mask = buf->depth-1UL;
  ulong distinct = 0UL;

  for( ulong seq=bank->first_seq; seq<=bank->last_seq; seq++ ) {
    fd_dragon_buf_hdr_t * hdr = fd_dragon_buf_entry( buf, bank, seq );
    if( !hdr || hdr->kind!=FD_DRAGON_BUF_ACCT ) continue;
    fd_dragon_buf_acct_t * acct = fd_dragon_buf_hdr_body( hdr );
    hdr->superseded = 0U;

    /* The table holds at most one slot per account of the bank, and a
       bank never has more entries than the ring, so a probe always
       ends at an empty slot or the account's own. */
    for( ulong h=buf_pubkey_hash( acct->pubkey ) & mask;; h=( h+1UL ) & mask ) {
      buf_dedup_slot_t * slot = buf->dedup + h;
      if( slot->gen!=gen ) {
        slot->gen = gen;
        slot->seq = seq;
        distinct++;
        break;
      }
      fd_dragon_buf_hdr_t *  prior_hdr  = fd_dragon_buf_entry( buf, bank, slot->seq );
      fd_dragon_buf_acct_t * prior      = fd_dragon_buf_hdr_body( prior_hdr );
      if( !fd_memeq( prior->pubkey, acct->pubkey, 32UL ) ) continue;

      /* The write with the higher write version is the state the block
         left the account in, whichever arrived first. */
      if( acct->write_version>=prior->write_version ) {
        prior_hdr->superseded = 1U;
        slot->seq             = seq;
      } else {
        hdr->superseded = 1U;
      }
      break;
    }
  }
  return distinct;
}

/* Accounting *********************************************************/

FD_FN_PURE ulong
fd_dragon_buf_bank_cnt( fd_dragon_buf_t const * buf ) {
  return buf->bank_cnt;
}

FD_FN_PURE ulong
fd_dragon_buf_entry_cnt( fd_dragon_buf_t const * buf ) {
  return buf->entry_cnt;
}

FD_FN_PURE ulong
fd_dragon_buf_byte_cnt( fd_dragon_buf_t const * buf ) {
  return buf->entry_cnt ? buf->pos-buf->oldest_pos : 0UL;
}

FD_FN_PURE ulong
fd_dragon_buf_byte_max( fd_dragon_buf_t const * buf ) {
  return buf->data_sz;
}

FD_FN_PURE ulong
fd_dragon_buf_depth( fd_dragon_buf_t const * buf ) {
  return buf->depth;
}

FD_FN_PURE fd_dragon_buf_metrics_t const *
fd_dragon_buf_metrics( fd_dragon_buf_t const * buf ) {
  return &buf->metrics;
}
