#include "fd_vinyl_bstream.h"

void
fd_vinyl_bstream_pair_hash( ulong                      seed,
                            fd_vinyl_bstream_block_t * hdr ) {

  ulong ctl     = hdr->ctl;
  ulong val_esz = fd_vinyl_bstream_ctl_sz( ctl );

  ulong pair_sz = fd_vinyl_bstream_pair_sz( val_esz );

  fd_vinyl_bstream_block_t * ftr = (fd_vinyl_bstream_block_t *)((uchar *)hdr + pair_sz - FD_VINYL_BSTREAM_BLOCK_SZ);

  ulong off = sizeof(fd_vinyl_bstream_phdr_t) + val_esz;
  ulong zsz = pair_sz - off; /* covers zpad and footer so at least FD_VINYL_BSTREAM_FTR_SZ */

  memset( (uchar *)hdr + off, 0, zsz );

  ulong hash_trail  = fd_vinyl_bstream_hash( seed,       hdr+1, pair_sz - FD_VINYL_BSTREAM_BLOCK_SZ );
  ulong hash_blocks = fd_vinyl_bstream_hash( hash_trail, hdr,             FD_VINYL_BSTREAM_BLOCK_SZ );

  ftr->ftr.hash_trail  = hash_trail;
  ftr->ftr.hash_blocks = hash_blocks;
}

char const *
fd_vinyl_bstream_pair_test( ulong                            seed,
                            ulong                            seq,
                            fd_vinyl_bstream_block_t const * hdr,
                            ulong                            buf_sz ) {
  (void)seq;

  if( FD_UNLIKELY( !hdr                             ) ) return "NULL buf";
  if( FD_UNLIKELY( buf_sz<FD_VINYL_BSTREAM_BLOCK_SZ ) ) return "buf_sz too small";

  ulong pair_ctl     = hdr->ctl;
  int   pair_type    = fd_vinyl_bstream_ctl_type( pair_ctl );
  ulong pair_val_esz = fd_vinyl_bstream_ctl_sz  ( pair_ctl );
  ulong pair_val_sz  = (ulong)hdr->phdr.info._val_sz;

  ulong pair_sz = fd_vinyl_bstream_pair_sz( pair_val_esz );

  if( FD_UNLIKELY( pair_type   != FD_VINYL_BSTREAM_CTL_TYPE_PAIR ) ) return "unexpected type";
  if( FD_UNLIKELY( pair_val_sz >  FD_VINYL_VAL_MAX               ) ) return "unexpected val size";
  if( FD_UNLIKELY( buf_sz      <  pair_sz                        ) ) return "truncated pair";

  fd_vinyl_bstream_block_t * ftr = (fd_vinyl_bstream_block_t *)((ulong)hdr + pair_sz - FD_VINYL_BSTREAM_BLOCK_SZ);

  ulong hash_trail  = ftr->ftr.hash_trail;
  ulong hash_blocks = ftr->ftr.hash_blocks;

  ftr->ftr.hash_trail  = 0UL;
  ftr->ftr.hash_blocks = 0UL;

  /* FIXME: test zero padding? */

  if( FD_UNLIKELY( fd_vinyl_bstream_hash( seed,       hdr+1, pair_sz - FD_VINYL_BSTREAM_BLOCK_SZ ) != hash_trail ) )
    return "unexpected trailing hash";

  if( FD_UNLIKELY( fd_vinyl_bstream_hash( hash_trail, hdr,             FD_VINYL_BSTREAM_BLOCK_SZ ) != hash_blocks ) )
    return "unexpected pair hash";

  return NULL;
}

char const *
fd_vinyl_bstream_pair_test_fast( ulong                            seed,
                                 ulong                            seq,
                                 fd_vinyl_bstream_block_t const * hdr,
                                 fd_vinyl_bstream_block_t *       ftr ) {
  (void)seq;

  if( FD_UNLIKELY( !hdr ) ) return "NULL hdr";
  if( FD_UNLIKELY( !ftr ) ) return "NULL ftr";

  ulong pair_ctl     = hdr->ctl;
  int   pair_type    = fd_vinyl_bstream_ctl_type( pair_ctl );
  ulong pair_val_esz = fd_vinyl_bstream_ctl_sz  ( pair_ctl );
  ulong pair_val_sz  = (ulong)hdr->phdr.info._val_sz;

  ulong pair_sz = fd_vinyl_bstream_pair_sz( pair_val_esz );

  if( FD_UNLIKELY( pair_type   != FD_VINYL_BSTREAM_CTL_TYPE_PAIR ) ) return "unexpected type";
  if( FD_UNLIKELY( pair_val_sz >  FD_VINYL_VAL_MAX               ) ) return "unexpected pair val size";

  ulong hash_trail  = ftr->ftr.hash_trail;
  ulong hash_blocks = ftr->ftr.hash_blocks;

  ftr->ftr.hash_trail  = 0UL;
  ftr->ftr.hash_blocks = 0UL;

  if( FD_UNLIKELY( pair_sz <= 2UL*FD_VINYL_BSTREAM_BLOCK_SZ                                                     ) &&
      FD_UNLIKELY( fd_vinyl_bstream_hash( seed,       ftr, pair_sz - FD_VINYL_BSTREAM_BLOCK_SZ ) != hash_trail  ) )
    return "unexpected trailing hash";

  if( FD_UNLIKELY( fd_vinyl_bstream_hash( hash_trail, hdr,           FD_VINYL_BSTREAM_BLOCK_SZ ) != hash_blocks ) )
    return "unexpected pair hash";

  return NULL;
}

char const *
fd_vinyl_bstream_dead_test( ulong                      seed,
                            ulong                      seq,
                            fd_vinyl_bstream_block_t * block ) {

  if( FD_UNLIKELY( !block ) ) return "NULL block";

  ulong dead_info_sz = block->dead.info_sz;

  int bad_ctl         = (block->dead.ctl != fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_DEAD,
                                                                  FD_VINYL_BSTREAM_CTL_STYLE_RAW,
                                                                  FD_VINYL_BSTREAM_BLOCK_SZ ) );
  int bad_match       = fd_vinyl_seq_ne( block->dead.seq, seq );
  int bad_seq         = (!fd_ulong_is_aligned( block->dead.seq, FD_VINYL_BSTREAM_BLOCK_SZ ));
  int bad_pair_type   = (fd_vinyl_bstream_ctl_type( block->dead.phdr.ctl ) != FD_VINYL_BSTREAM_CTL_TYPE_PAIR);
  int bad_pair_val_sz = ((ulong)block->dead.phdr.info._val_sz > FD_VINYL_VAL_MAX);
  int bad_info_sz     = (dead_info_sz > FD_VINYL_BSTREAM_DEAD_INFO_MAX);

  if( FD_UNLIKELY( bad_ctl | bad_match | bad_seq | bad_pair_type | bad_pair_val_sz | bad_info_sz ) )
    return bad_ctl         ? "unexpected dead ctl"           :
           bad_match       ? "mismatched dead seq"           :
           bad_seq         ? "misaligned dead seq"           :
           bad_pair_type   ? "unexpected dead pair type"     :
           bad_pair_val_sz ? "unexpected dead pair val size" :
                             "unexpected dead info size";

  for( ulong zpad_idx=dead_info_sz; zpad_idx<FD_VINYL_BSTREAM_DEAD_INFO_MAX; zpad_idx++ )
    if( FD_UNLIKELY( block->dead.info[ zpad_idx ] ) ) return "data in zero padding";

  if( FD_UNLIKELY( fd_vinyl_bstream_block_test( seed, block ) ) ) return "corrupt block";

  return NULL;
}

char const *
fd_vinyl_bstream_move_test( ulong                      seed,
                            ulong                      seq,
                            fd_vinyl_bstream_block_t * block,
                            fd_vinyl_bstream_block_t * dst ) {

  if( FD_UNLIKELY( !block ) ) return "NULL block";
  if( FD_UNLIKELY( !dst   ) ) return "NULL dst";

  ulong move_info_sz = block->move.info_sz;

  int bad_ctl        = (block->move.ctl != fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_MOVE,
                                                                 FD_VINYL_BSTREAM_CTL_STYLE_RAW,
                                                                 FD_VINYL_BSTREAM_BLOCK_SZ ) );
  int bad_match      = fd_vinyl_seq_ne( block->move.seq, seq );
  int bad_seq        = (!fd_ulong_is_aligned( block->move.seq, FD_VINYL_BSTREAM_BLOCK_SZ ));
  int bad_src_type   = (fd_vinyl_bstream_ctl_type( block->move.src.ctl ) != FD_VINYL_BSTREAM_CTL_TYPE_PAIR);
  int bad_src_val_sz = ((ulong)block->move.src.info._val_sz > FD_VINYL_VAL_MAX);
  int bad_move       = fd_vinyl_key_eq( &block->move.src.key, &block->move.dst );
  int bad_info_sz    = (move_info_sz > FD_VINYL_BSTREAM_MOVE_INFO_MAX);
  int bad_dst_type   = (fd_vinyl_bstream_ctl_type( dst->phdr.ctl ) != FD_VINYL_BSTREAM_CTL_TYPE_PAIR);
  int bad_dst_key    = (!fd_vinyl_key_eq( &block->move.dst, &dst->phdr.key ));
  int bad_dst_info   = (!!memcmp( &block->move.src.info, &dst->phdr.info, FD_VINYL_INFO_SZ ));

  if( FD_UNLIKELY( bad_ctl | bad_match | bad_seq | bad_src_type | bad_src_val_sz | bad_move | bad_info_sz |
                   bad_dst_type | bad_dst_key | bad_dst_info ) )
    return bad_ctl        ? "unexpected move ctl"          :
           bad_match      ? "mismatched move seq"          :
           bad_seq        ? "misaligned move seq"          :
           bad_src_type   ? "unexpected move src type"     :
           bad_src_val_sz ? "unexpected move src val size" :
           bad_move       ? "dst key matches src key"      :
           bad_info_sz    ? "unexpected move info size"    :
           bad_dst_type   ? "mismatched move dst type"     :
           bad_dst_key    ? "mismatched move dst key"      :
                            "mismatched move dst info";

  for( ulong zpad_idx=move_info_sz; zpad_idx<FD_VINYL_BSTREAM_MOVE_INFO_MAX; zpad_idx++ )
    if( FD_UNLIKELY( block->move.info[ zpad_idx ] ) ) return "data in zero padding";

  if( FD_UNLIKELY( fd_vinyl_bstream_block_test( seed, block ) ) ) return "corrupt block";

  return NULL;
}

char const *
fd_vinyl_bstream_part_test( ulong                      seed,
                            ulong                      seq,
                            fd_vinyl_bstream_block_t * block ) {

  if( FD_UNLIKELY( !block ) ) return "NULL block";

  ulong part_seq      = block->part.seq;
  ulong part_seq0     = block->part.seq0;
  ulong part_dead_cnt = block->part.dead_cnt;
  ulong part_move_cnt = block->part.move_cnt;
  ulong part_info_sz  = block->part.info_sz;

  ulong part_block_cnt = (part_seq - part_seq0) / FD_VINYL_BSTREAM_BLOCK_SZ;

  int bad_ctl       = (block->part.ctl != fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PART,
                                                                FD_VINYL_BSTREAM_CTL_STYLE_RAW,
                                                                FD_VINYL_BSTREAM_BLOCK_SZ ) );
  int bad_match     = fd_vinyl_seq_ne( block->part.seq, seq );
  int bad_seq       = (!fd_ulong_is_aligned( part_seq,  FD_VINYL_BSTREAM_BLOCK_SZ ));
  int bad_seq0      = (!fd_ulong_is_aligned( part_seq0, FD_VINYL_BSTREAM_BLOCK_SZ ));
  int bad_order     = fd_vinyl_seq_gt( part_seq0, part_seq );
  int bad_dead_cnt  = (part_dead_cnt                     > part_block_cnt);
  int bad_move_cnt  = ((2UL*part_move_cnt)               > part_block_cnt);
  int bad_block_cnt = ((part_dead_cnt+2UL*part_move_cnt) > part_block_cnt);
  int bad_info_sz   = (part_info_sz > FD_VINYL_BSTREAM_PART_INFO_MAX);

  if( FD_UNLIKELY( bad_ctl | bad_match | bad_seq | bad_seq0 | bad_order |
                   bad_dead_cnt | bad_move_cnt | bad_block_cnt | bad_info_sz ) )
    return bad_ctl       ? "unexpected partition ctl"             :
           bad_match     ? "mismatched partition seq"             :
           bad_seq       ? "misaligned partition seq"             :
           bad_seq0      ? "misaligned partition seq previous"    :
           bad_order     ? "unordered partition seq/seq previous" :
           bad_dead_cnt  ? "unexpected partition dead count"      :
           bad_move_cnt  ? "unexpected partition move count"      :
           bad_block_cnt ? "unexpected partition block count"     :
                           "unexpected partition info size";

  for( ulong zpad_idx=part_info_sz; zpad_idx<FD_VINYL_BSTREAM_PART_INFO_MAX; zpad_idx++ )
    if( FD_UNLIKELY( block->part.info[ zpad_idx ] ) ) return "data in zero padding";

  if( FD_UNLIKELY( fd_vinyl_bstream_block_test( seed, block ) ) ) return "corrupt block";

  return NULL;
}

char const *
fd_vinyl_bstream_zpad_test( ulong                            seed,
                            ulong                            seq,
                            fd_vinyl_bstream_block_t const * block ) {
  (void)seed; (void)seq;

  if( FD_UNLIKELY( !block ) ) return "NULL block";

  ulong const * buf = (ulong const *)block->zpad;
  ulong         cnt = FD_VINYL_BSTREAM_BLOCK_SZ / sizeof(ulong);

  for( ulong idx=0UL; idx<cnt; idx++ ) if( FD_UNLIKELY( buf[idx] ) ) return "data in zero padding";

  return NULL;
}

char const *
fd_vinyl_bstream_ctl_style_cstr( int style ) {
  switch( style ) {
  case     FD_VINYL_BSTREAM_CTL_STYLE_RAW: return "raw";
  case     FD_VINYL_BSTREAM_CTL_STYLE_LZ4: return "lz4";
  default: break;
  }
  return "unk";
}

int
fd_cstr_to_vinyl_bstream_ctl_style( char const * cstr ) {
  if( FD_UNLIKELY( !cstr ) ) return -1;
  if( !fd_cstr_casecmp( cstr, "raw" ) ) return FD_VINYL_BSTREAM_CTL_STYLE_RAW;
  if( !fd_cstr_casecmp( cstr, "lz4" ) ) return FD_VINYL_BSTREAM_CTL_STYLE_LZ4;
  return -1;
}
