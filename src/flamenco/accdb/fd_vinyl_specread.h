#ifndef HEADER_fd_src_flamenco_accdb_fd_vinyl_specread_h
#define HEADER_fd_src_flamenco_accdb_fd_vinyl_specread_h

#include "../../vinyl/line/fd_vinyl_line.h"

/* fd_vinyl_specread speculatively queries a key from vinyl cache.
   Requires x86-TSO.

   Returns:
     FD_VINYL_SUCCESS   - data copied to dst, *_val_sz and *_info set
     FD_VINYL_ERR_KEY   - key does not exist in vinyl meta
     FD_VINYL_ERR_AGAIN - speculative read failed; caller should fall
                          back to rq/cq */

FD_FN_UNUSED static int
fd_vinyl_specread( fd_vinyl_meta_t const *  meta,
                   fd_vinyl_line_t const *  line,
                   ulong                    line_cnt,
                   void *                   data_laddr0,
                   fd_vinyl_key_t const *   key,
                   void *                   dst,
                   ulong                    dst_max,
                   ulong *                  _val_sz,
                   fd_vinyl_info_t *        _info ) {

  /* Phase 1: Meta seqlock query */

  fd_vinyl_meta_query_t query[1];
  int err = fd_vinyl_meta_query_try(
      (fd_vinyl_meta_t *)meta, key, NULL, query, 0 );
  if( FD_UNLIKELY( err ) ) return err; /* ERR_KEY or ERR_AGAIN */

  fd_vinyl_meta_ele_t const * ele =
      fd_vinyl_meta_query_ele_const( query );

  ulong pair_ctl = ele->phdr.ctl;
  if( FD_UNLIKELY( pair_ctl==ULONG_MAX ) ) return FD_VINYL_ERR_AGAIN;

  ulong           val_sz   = (ulong)ele->phdr.info.val_sz;
  fd_vinyl_info_t info     = ele->phdr.info;
  ulong           ele_idx  = (ulong)( ele - meta->ele );
  ulong           line_idx = ele->line_idx;

  if( FD_UNLIKELY( fd_vinyl_meta_query_test( query ) ) )
    return FD_VINYL_ERR_AGAIN;

  if( FD_UNLIKELY( line_idx>=line_cnt ) )
    return FD_VINYL_ERR_AGAIN;

  /* Phase 2: Line seqlock + cross-validation */

  FD_COMPILER_MFENCE();
  ulong ctl_before = FD_VOLATILE_CONST( line[ line_idx ].ctl );
  FD_COMPILER_MFENCE();

  ulong ver = fd_vinyl_line_ctl_ver( ctl_before );
  long  ref = fd_vinyl_line_ctl_ref( ctl_before );

  if( FD_UNLIKELY( ref<0L ) )
    return FD_VINYL_ERR_AGAIN;

  if( FD_UNLIKELY( line[ line_idx ].ele_idx!=ele_idx ) )
    return FD_VINYL_ERR_AGAIN;

  ulong val_gaddr = line[ line_idx ].val_gaddr;
  if( FD_UNLIKELY( !val_gaddr ) )
    return FD_VINYL_ERR_AGAIN;

  /* Phase 3: Read data */

  ulong copy_sz = fd_ulong_min( val_sz, dst_max );
  void const * src = fd_vinyl_data_laddr( val_gaddr, data_laddr0 );
  fd_memcpy( dst, src, copy_sz );

  /* Phase 4: Validate */

  FD_COMPILER_MFENCE();
  ulong ctl_after = FD_VOLATILE_CONST( line[ line_idx ].ctl );
  FD_COMPILER_MFENCE();

  if( FD_UNLIKELY( fd_vinyl_line_ctl_ver( ctl_after )!=ver ) )
    return FD_VINYL_ERR_AGAIN;

  if( FD_UNLIKELY( copy_sz<val_sz ) )
    return FD_VINYL_ERR_AGAIN;

  *_val_sz = copy_sz;
  *_info   = info;
  return FD_VINYL_SUCCESS;
}

#endif /* HEADER_fd_src_flamenco_accdb_fd_vinyl_specread_h */
