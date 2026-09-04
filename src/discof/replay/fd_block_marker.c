#include "fd_block_marker.h"

#include "../../ballet/bls/fd_bls12_381.h"
#include "../../ballet/txn/fd_compact_u16.h"
#include "../../choreo/votor/ag_cert_serde.h"


#define CHECK_LEFT( n ) do {                                            \
  if( FD_UNLIKELY( (n)>rem ) ) return FD_BLOCK_MARKER_DE_ERR_TRUNCATED; \
} while( 0 )

#define ADVANCE( n ) do { buf += (n); rem -= (n); } while( 0 )

static int
option_de( uchar const ** _buf,
           ulong *        _rem,
           int *          present ) {
  uchar const * buf = *_buf;
  ulong         rem = *_rem;
  CHECK_LEFT( 1UL );
  if( FD_UNLIKELY( buf[0]>1 ) ) return FD_BLOCK_MARKER_DE_ERR_MALFORMED;
  *present = buf[0];
  ADVANCE( 1UL );
  *_buf = buf; *_rem = rem;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

/* reward_cert_de deserializes a SkipRewardCertificate
   (has_block_id=0) or a NotarRewardCertificate (has_block_id=1):

     slot (8) | [block_id (32)] | compressed BLS signature (96) |
     bitmap byte count (ushort) | bitmap

   where bitmap is a base2 bitmap: version (1) | bit count (u16 LE) |
   payload.  Only base2 bitmaps are accepted. */

static int
reward_cert_de( fd_reward_cert_t * cert,
                uchar const **     _buf,
                ulong *            _rem,
                int                has_block_id ) {
  uchar const * buf = *_buf;
  ulong         rem = *_rem;

  ulong block_id_sz = has_block_id ? sizeof(fd_hash_t) : 0UL;
  CHECK_LEFT( 8UL+block_id_sz+AG_BLS_SIG_COMPRESSED_SZ );
  cert->slot = FD_LOAD( ulong, buf );
  fd_memset( cert->block_id.uc, 0, sizeof(fd_hash_t) );
  if( has_block_id ) fd_memcpy( cert->block_id.uc, buf+8UL, sizeof(fd_hash_t) );
  fd_memcpy( cert->sig, buf+8UL+block_id_sz, AG_BLS_SIG_COMPRESSED_SZ );
  ADVANCE( 8UL+block_id_sz+AG_BLS_SIG_COMPRESSED_SZ );

  /* bit map */
  ulong cu16_sz = fd_cu16_dec_sz( buf, rem );
  if( FD_UNLIKELY( !cu16_sz ) ) return FD_BLOCK_MARKER_DE_ERR_MALFORMED;
  ulong bitmap_sz = (ulong)fd_cu16_dec_fixed( buf, cu16_sz );
  ADVANCE( cu16_sz );
  CHECK_LEFT( bitmap_sz );

  if( FD_UNLIKELY( bitmap_sz<3UL ) ) return FD_BLOCK_MARKER_DE_ERR_MALFORMED;
  if( FD_UNLIKELY( buf[0]!=0     ) ) return FD_BLOCK_MARKER_DE_ERR_MALFORMED; /* base2 */
  ulong nbits = (ulong)FD_LOAD( ushort, buf+1UL );
  if( FD_UNLIKELY( nbits>AG_VAT_MAX               ) ) return FD_BLOCK_MARKER_DE_ERR_MALFORMED;
  if( FD_UNLIKELY( bitmap_sz-3UL!=(nbits+7UL)/8UL ) ) return FD_BLOCK_MARKER_DE_ERR_MALFORMED;
  cert->nbits = (ushort)nbits;
  fd_memset( cert->signer_set, 0, sizeof(cert->signer_set) );
  uchar const * payload = buf+3UL;
  for( ulong r=0UL; r<nbits; r++ ) {
    if( payload[ r>>3 ] & (uchar)(1U<<(r&7U)) ) cert->signer_set[ r>>6 ] |= 1UL<<(r&63UL);
  }
  ADVANCE( bitmap_sz );

  *_buf = buf; *_rem = rem;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

/* votes_aggregate_de deserializes a VotesAggregate.  The bitmap is the
   same solana_signer_store encoding the wire framing uses, so the codes
   returned here are AG_CERT_DE_*; the only caller just tests for
   nonzero.  nbits receives the bitmap's declared width
   (solana_signer_store num_bits), which the set bits alone cannot
   recover and which verification has to bound by the epoch's validator
   count, as agave's decode( bytes, max_len ) does. */

static int
votes_aggregate_de( ag_bls_agg_t * agg,
                    ushort *       nbits,
                    uchar const *  buf,
                    ulong          buf_max,
                    ulong *        buf_sz ) {
  if( FD_UNLIKELY( buf_max<sizeof(fd_block_votes_aggregate_serde_t) ) ) return AG_CERT_DE_ERR_SZ;
  fd_block_votes_aggregate_serde_t const * aggregate = (fd_block_votes_aggregate_serde_t const *)buf;

  ulong  sz     = sizeof(fd_block_votes_aggregate_serde_t);
  ushort bm_cnt = aggregate->bitmap_cnt;
  if( FD_UNLIKELY( bm_cnt>buf_max-sz ) ) return AG_CERT_DE_ERR_SZ;

  int err = ag_bls_agg_de( agg, buf+sz, bm_cnt );  if( FD_UNLIKELY( err ) ) return err;
  memcpy( agg->sig, aggregate->signature, AG_BLS_SIG_COMPRESSED_SZ );
  *nbits  = FD_LOAD( ushort, buf+sz+1UL ); /* bitmap header: version (1) | num_bits (u16 LE) */
  *buf_sz = sz + bm_cnt;
  return AG_CERT_DE_SUCCESS;
}

static int
decompress( ag_bls_agg_t * agg ) {
  uchar csig[ AG_BLS_SIG_COMPRESSED_SZ ];
  memcpy( csig, agg->sig, AG_BLS_SIG_COMPRESSED_SZ );
  return fd_bls12_381_g2_decompress_syscall( agg->sig, csig, 1 );
}

int
fd_block_final_cert_de( ag_cert_fast_final_t * fast_final,
                        ag_cert_final_t *      final,
                        ag_cert_notar_t *      notar,
                        ushort *               final_agg_nbits,
                        ushort *               notar_agg_nbits,
                        uchar const *          buf,
                        ulong                  buf_max,
                        ulong *                buf_sz ) {
  ulong remaining = buf_max;
  *final_agg_nbits = 0;
  *notar_agg_nbits = 0;

  if( FD_UNLIKELY( remaining<sizeof(fd_block_final_cert_serde_t) ) ) return -1;
  fd_block_final_cert_serde_t const * block_final = (fd_block_final_cert_serde_t const *)buf;
  buf       += sizeof(fd_block_final_cert_serde_t);
  remaining -= sizeof(fd_block_final_cert_serde_t);

  ag_bls_agg_t final_agg[1];
  ulong        consumed;
  if( FD_UNLIKELY( votes_aggregate_de( final_agg, final_agg_nbits, buf, remaining, &consumed ) ) ) return -1;
  buf       += consumed;
  remaining -= consumed;

  if( FD_UNLIKELY( remaining<1UL ) ) return -1;
  uchar has_notar_aggregate = *buf;
  buf       += 1UL;
  remaining -= 1UL;
  if( FD_UNLIKELY( has_notar_aggregate>1 ) ) return -1;

  if( !has_notar_aggregate ) {
    fd_memset( fast_final, 0, sizeof(ag_cert_fast_final_t) );
    fast_final->slot    = block_final->slot;
    fast_final->agg_sig = *final_agg;
    memcpy( fast_final->block_hash, block_final->block_id, sizeof(ag_block_hash_t) );
    if( FD_UNLIKELY( decompress( &fast_final->agg_sig ) ) ) return -1;
    if( buf_sz ) *buf_sz = buf_max - remaining;
    return 1;
  }

  ag_bls_agg_t notar_agg[1];
  if( FD_UNLIKELY( votes_aggregate_de( notar_agg, notar_agg_nbits, buf, remaining, &consumed ) ) ) return -1;
  remaining -= consumed;

  fd_memset( final, 0, sizeof(ag_cert_final_t) );
  fd_memset( notar, 0, sizeof(ag_cert_notar_t) );
  final->slot    = block_final->slot;
  final->agg_sig = *final_agg;
  notar->slot    = block_final->slot;
  notar->agg_sig = *notar_agg;
  memcpy( notar->block_hash, block_final->block_id, sizeof(ag_block_hash_t) );
  if( FD_UNLIKELY( decompress( &final->agg_sig ) ) ) return -1;
  if( FD_UNLIKELY( decompress( &notar->agg_sig ) ) ) return -1;
  if( buf_sz ) *buf_sz = buf_max - remaining;
  return 0;
}

int
fd_block_header_de( fd_block_header_t * header,
                    uchar const *       buf,
                    ulong               buf_max,
                    ulong *             buf_sz ) {
  ulong rem = buf_max;

  CHECK_LEFT( 1UL );
  if( FD_UNLIKELY( buf[0]!=1 ) ) return FD_BLOCK_MARKER_DE_ERR_UNSUPPORTED; /* VersionedBlockHeader tag */
  ADVANCE( 1UL );

  CHECK_LEFT( 8UL+sizeof(fd_hash_t) );
  header->parent_slot = FD_LOAD( ulong, buf );
  fd_memcpy( header->parent_block_id.uc, buf+8UL, sizeof(fd_hash_t) );
  ADVANCE( 8UL+sizeof(fd_hash_t) );

  if( buf_sz ) *buf_sz = buf_max-rem;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

int
fd_update_parent_de( fd_update_parent_t * update_parent,
                     uchar const *        buf,
                     ulong                buf_max,
                     ulong *              buf_sz ) {
  ulong rem = buf_max;

  CHECK_LEFT( 1UL );
  if( FD_UNLIKELY( buf[0]!=1 ) ) return FD_BLOCK_MARKER_DE_ERR_UNSUPPORTED; /* VersionedUpdateParent tag */
  ADVANCE( 1UL );

  CHECK_LEFT( 8UL+sizeof(fd_hash_t) );
  update_parent->new_parent_slot = FD_LOAD( ulong, buf );
  fd_memcpy( update_parent->new_parent_block_id.uc, buf+8UL, sizeof(fd_hash_t) );
  ADVANCE( 8UL+sizeof(fd_hash_t) );

  if( buf_sz ) *buf_sz = buf_max-rem;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

int
fd_block_footer_de( fd_block_footer_t * footer,
                    uchar const *       buf,
                    ulong               buf_max,
                    ulong *             buf_sz ) {
  ulong rem = buf_max;
  int   err;

  footer->has_fast_final_cert   = 0;
  footer->has_final_cert        = 0;
  footer->final_agg_nbits       = 0;
  footer->notar_agg_nbits       = 0;
  footer->has_skip_reward_cert  = 0;
  footer->has_notar_reward_cert = 0;

  CHECK_LEFT( 1UL );
  if( FD_UNLIKELY( buf[0]!=1 ) ) return FD_BLOCK_MARKER_DE_ERR_UNSUPPORTED; /* VersionedBlockFooter tag */
  ADVANCE( 1UL );

  CHECK_LEFT( sizeof(fd_hash_t)+8UL+1UL );
  fd_memcpy( footer->bank_hash.uc, buf, sizeof(fd_hash_t) );
  footer->block_producer_time_nanos = FD_LOAD( ulong, buf+sizeof(fd_hash_t) );
  footer->user_agent_len            = (ulong)buf[ sizeof(fd_hash_t)+8UL ];
  ADVANCE( sizeof(fd_hash_t)+8UL+1UL );

  CHECK_LEFT( footer->user_agent_len );
  fd_memcpy( footer->user_agent, buf, footer->user_agent_len );
  ADVANCE( footer->user_agent_len );

  int present;
  if( FD_UNLIKELY( (err=option_de( &buf, &rem, &present )) ) ) return err;
  if( present ) {
    ulong consumed;
    int   is_fast = fd_block_final_cert_de( &footer->fast_final_cert, &footer->final_cert, &footer->notar_cert, &footer->final_agg_nbits, &footer->notar_agg_nbits, buf, rem, &consumed );
    if( FD_UNLIKELY( is_fast<0 ) ) return FD_BLOCK_MARKER_DE_ERR_MALFORMED;
    footer->has_fast_final_cert = is_fast==1;
    footer->has_final_cert      = is_fast==0;
    ADVANCE( consumed );
  }

  if( FD_UNLIKELY( (err=option_de( &buf, &rem, &present )) ) ) return err;
  if( present ) {
    if( FD_UNLIKELY( (err=reward_cert_de( &footer->skip_reward_cert, &buf, &rem, 0 )) ) ) return err;
    footer->has_skip_reward_cert = 1;
  }

  if( FD_UNLIKELY( (err=option_de( &buf, &rem, &present )) ) ) return err;
  if( present ) {
    if( FD_UNLIKELY( (err=reward_cert_de( &footer->notar_reward_cert, &buf, &rem, 1 )) ) ) return err;
    footer->has_notar_reward_cert = 1;
  }

  if( buf_sz ) *buf_sz = buf_max-rem;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

int
fd_block_marker_de( fd_block_marker_t * marker,
                    uchar const *       buf,
                    ulong               buf_max,
                    ulong *             buf_sz ) {
  ulong rem = buf_max;

  CHECK_LEFT( FD_BLOCK_MARKER_PREAMBLE_SZ );
  if( FD_UNLIKELY( FD_LOAD( ulong,  buf     )!=0UL ) ) return FD_BLOCK_MARKER_DE_ERR_MALFORMED;   /* marker flag */
  if( FD_UNLIKELY( FD_LOAD( ushort, buf+8UL )!=1   ) ) return FD_BLOCK_MARKER_DE_ERR_UNSUPPORTED; /* VersionedBlockMarker tag */
  uchar variant = buf[ 10UL ];
  ulong length  = (ulong)FD_LOAD( ushort, buf+11UL );
  ADVANCE( FD_BLOCK_MARKER_PREAMBLE_SZ );

  CHECK_LEFT( length );

  marker->variant = variant;

  /* payload deserializer may consume less than length */
  int err;
  switch( variant ) {
    case FOOTER:        err = fd_block_footer_de ( &marker->footer,        buf, length, NULL ); break;
    case HEADER:        err = fd_block_header_de ( &marker->header,        buf, length, NULL ); break;
    case UPDATE_PARENT: err = fd_update_parent_de( &marker->update_parent, buf, length, NULL ); break;
    case GENESIS_CERTIFICATE: return FD_BLOCK_MARKER_DE_ERR_UNSUPPORTED;
    default:                  return FD_BLOCK_MARKER_DE_ERR_MALFORMED;
  }
  if( FD_UNLIKELY( err ) ) return err;
  ADVANCE( length );

  if( buf_sz ) *buf_sz = buf_max-rem;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

FD_STATIC_ASSERT( sizeof(fd_block_marker_serde_t         )==FD_BLOCK_MARKER_PREAMBLE_SZ,  fd_block_marker_serde );
FD_STATIC_ASSERT( sizeof(fd_block_header_serde_t         )==41UL,                         fd_block_marker_serde );
FD_STATIC_ASSERT( sizeof(fd_block_footer_serde_t         )==42UL,                         fd_block_marker_serde );
FD_STATIC_ASSERT( sizeof(fd_block_votes_aggregate_serde_t)==AG_BLS_SIG_COMPRESSED_SZ+2UL, fd_block_marker_serde );
FD_STATIC_ASSERT( sizeof(fd_block_final_cert_serde_t     )==8UL+sizeof(ag_block_hash_t),  fd_block_marker_serde );

#define CHECK_SPACE( n ) do {                                          \
  if( FD_UNLIKELY( (n)>rem ) ) return FD_BLOCK_MARKER_SER_ERR_NOSPACE; \
} while( 0 )

static int
block_header_ser( fd_block_header_t const * header,
                  uchar **                  _buf,
                  ulong *                   _rem ) {
  uchar * buf = *_buf;
  ulong   rem = *_rem;

  CHECK_SPACE( sizeof(fd_block_header_serde_t) );
  fd_block_header_serde_t * out = (fd_block_header_serde_t *)buf;
  out->version     = (uchar)1;
  out->parent_slot = header->parent_slot;
  fd_memcpy( out->parent_block_id, header->parent_block_id.uc, sizeof(out->parent_block_id) );
  ADVANCE( sizeof(fd_block_header_serde_t) );

  *_buf = buf; *_rem = rem;
  return FD_BLOCK_MARKER_SER_SUCCESS;
}

/* base2_bitmap_ser writes the solana_signer_store base2 bitmap naming
   the ranks in [0,bit_cnt) that are set in words: a version byte, the
   bit count, and ceil(bit_cnt/8) payload bytes.  Returns the number of
   bytes written, which the caller must have reserved.

   TODO fold into ag_bls_agg_ser once the encoder ag_cert_serde.c keeps
   private moves to ag_bls_serde. */

static ulong
base2_bitmap_ser( uchar *       buf,
                  ulong const * words,
                  ulong         bit_cnt ) {
  ulong payload_sz = (bit_cnt+7UL)/8UL;
  buf[ 0 ] = 0; /* base2 */
  FD_STORE( ushort, buf+1UL, (ushort)bit_cnt );
  fd_memset( buf+3UL, 0, payload_sz );
  for( ulong r=0UL; r<bit_cnt; r++ ) {
    if( words[ r>>6 ] & (1UL<<(r&63UL)) ) buf[ 3UL+(r>>3) ] |= (uchar)( 1U<<(r&7U) );
  }
  return 3UL+payload_sz;
}

/* agg_bit_cnt is the bitmap width Agave emits for an aggregate: one
   past the highest signing rank, or zero when nobody signed. */

static ulong
agg_bit_cnt( ag_bls_agg_t const * agg ) {
  ulong last = signer_set_last( agg->bitmask );
  return fd_ulong_if( last>=AG_BLS_SIGNERS_MAX, 0UL, last+1UL );
}

/* votes_aggregate_ser mirrors votes_aggregate_de: a compressed BLS
   signature followed by a base2 bitmap under a u16 byte count.  The
   aggregate carries the decompressed signature, so it is compressed
   back here. */

static int
votes_aggregate_ser( ag_bls_agg_t const * agg,
                     uchar **             _buf,
                     ulong *              _rem ) {
  uchar * buf = *_buf;
  ulong   rem = *_rem;

  ulong bit_cnt = agg_bit_cnt( agg );
  if( FD_UNLIKELY( bit_cnt>AG_VAT_MAX ) ) return FD_BLOCK_MARKER_SER_ERR_UNSUPPORTED; /* would breach FD_BLOCK_FOOTER_SER_MAX */
  ulong bitmap_sz = 3UL+(bit_cnt+7UL)/8UL;

  CHECK_SPACE( sizeof(fd_block_votes_aggregate_serde_t)+bitmap_sz );
  fd_block_votes_aggregate_serde_t * out = (fd_block_votes_aggregate_serde_t *)buf;
  if( FD_UNLIKELY( fd_bls12_381_g2_compress( out->signature, agg->sig, 1 ) ) ) return FD_BLOCK_MARKER_SER_ERR_MALFORMED;
  out->bitmap_cnt = (ushort)bitmap_sz;
  base2_bitmap_ser( buf+sizeof(fd_block_votes_aggregate_serde_t), agg->bitmask, bit_cnt );
  ADVANCE( sizeof(fd_block_votes_aggregate_serde_t)+bitmap_sz );

  *_buf = buf; *_rem = rem;
  return FD_BLOCK_MARKER_SER_SUCCESS;
}

/* block_final_cert_ser mirrors fd_block_final_cert_de.  A fast
   finalization writes one aggregate and a zero has_notar_aggregate
   byte; a slow one writes the final aggregate, a one byte, and the
   notar aggregate.  Only one block_id goes on the wire and in the slow
   case it is the notar cert's, so the two certs must name one slot. */

static int
block_final_cert_ser( fd_block_footer_t const * footer,
                      uchar **                  _buf,
                      ulong *                   _rem ) {
  uchar * buf = *_buf;
  ulong   rem = *_rem;
  int     err;

  int           is_fast  = footer->has_fast_final_cert;
  ulong         slot     = is_fast ? footer->fast_final_cert.slot       : footer->final_cert.slot;
  uchar const * block_id = is_fast ? footer->fast_final_cert.block_hash : footer->notar_cert.block_hash;

  if( FD_UNLIKELY( !is_fast && footer->final_cert.slot!=footer->notar_cert.slot ) ) return FD_BLOCK_MARKER_SER_ERR_MALFORMED;

  CHECK_SPACE( sizeof(fd_block_final_cert_serde_t) );
  fd_block_final_cert_serde_t * out = (fd_block_final_cert_serde_t *)buf;
  out->slot = slot;
  memcpy( out->block_id, block_id, sizeof(ag_block_hash_t) );
  ADVANCE( sizeof(fd_block_final_cert_serde_t) );

  ag_bls_agg_t const * final_agg = is_fast ? &footer->fast_final_cert.agg_sig : &footer->final_cert.agg_sig;
  if( FD_UNLIKELY( (err=votes_aggregate_ser( final_agg, &buf, &rem )) ) ) return err;

  CHECK_SPACE( 1UL );
  buf[ 0 ] = (uchar)!is_fast; /* notar_aggregate */
  ADVANCE( 1UL );

  if( !is_fast ) {
    if( FD_UNLIKELY( (err=votes_aggregate_ser( &footer->notar_cert.agg_sig, &buf, &rem )) ) ) return err;
  }

  *_buf = buf; *_rem = rem;
  return FD_BLOCK_MARKER_SER_SUCCESS;
}

/* reward_cert_ser mirrors reward_cert_de.  The signature is already
   compressed and the bitmap byte count is a ShortU16 rather than the
   aggregate's u16.  nbits goes out as given so that a cert that came
   off the wire re-encodes to the same bytes; ranks at or above it are
   dropped. */

static int
reward_cert_ser( fd_reward_cert_t const * cert,
                 int                      has_block_id,
                 uchar **                 _buf,
                 ulong *                  _rem ) {
  uchar * buf = *_buf;
  ulong   rem = *_rem;

  ulong bit_cnt = (ulong)cert->nbits;
  if( FD_UNLIKELY( bit_cnt>AG_VAT_MAX ) ) return FD_BLOCK_MARKER_SER_ERR_UNSUPPORTED; /* would breach FD_BLOCK_FOOTER_SER_MAX */
  ulong block_id_sz = has_block_id ? sizeof(fd_hash_t) : 0UL;
  ulong bitmap_sz   = 3UL+(bit_cnt+7UL)/8UL;

  CHECK_SPACE( 8UL+block_id_sz+AG_BLS_SIG_COMPRESSED_SZ );
  FD_STORE( ulong, buf, cert->slot );
  if( has_block_id ) fd_memcpy( buf+8UL, cert->block_id.uc, sizeof(fd_hash_t) );
  memcpy( buf+8UL+block_id_sz, cert->sig, AG_BLS_SIG_COMPRESSED_SZ );
  ADVANCE( 8UL+block_id_sz+AG_BLS_SIG_COMPRESSED_SZ );

  uchar cu16[ 3 ];
  ulong cu16_sz = (ulong)fd_cu16_enc( (ushort)bitmap_sz, cu16 );
  CHECK_SPACE( cu16_sz+bitmap_sz );
  fd_memcpy( buf, cu16, cu16_sz );
  ADVANCE( cu16_sz );
  base2_bitmap_ser( buf, cert->signer_set, bit_cnt );
  ADVANCE( bitmap_sz );

  *_buf = buf; *_rem = rem;
  return FD_BLOCK_MARKER_SER_SUCCESS;
}

/* option_ser writes an Option tag.  The three footer options interleave
   tag and body, so a present cert's body follows its own tag rather
   than all three tags. */

static int
option_ser( int      present,
            uchar ** _buf,
            ulong *  _rem ) {
  uchar * buf = *_buf;
  ulong   rem = *_rem;

  CHECK_SPACE( 1UL );
  buf[ 0 ] = (uchar)!!present;
  ADVANCE( 1UL );

  *_buf = buf; *_rem = rem;
  return FD_BLOCK_MARKER_SER_SUCCESS;
}

static int
block_footer_ser( fd_block_footer_t const * footer,
                  uchar **                  _buf,
                  ulong *                   _rem ) {
  uchar * buf = *_buf;
  ulong   rem = *_rem;
  int     err;

  if( FD_UNLIKELY( footer->has_fast_final_cert && footer->has_final_cert ) ) return FD_BLOCK_MARKER_SER_ERR_MALFORMED;
  if( FD_UNLIKELY( footer->user_agent_len>FD_BLOCK_FOOTER_USER_AGENT_MAX ) ) return FD_BLOCK_MARKER_SER_ERR_UNSUPPORTED;

  CHECK_SPACE( sizeof(fd_block_footer_serde_t)+footer->user_agent_len );
  fd_block_footer_serde_t * out = (fd_block_footer_serde_t *)buf;
  out->version                   = (uchar)1;
  out->block_producer_time_nanos = footer->block_producer_time_nanos;
  out->user_agent_len            = (uchar)footer->user_agent_len;
  fd_memcpy( out->bank_hash, footer->bank_hash.uc, sizeof(out->bank_hash) );
  ADVANCE( sizeof(fd_block_footer_serde_t) );

  fd_memcpy( buf, footer->user_agent, footer->user_agent_len );
  ADVANCE( footer->user_agent_len );

  int has_block_final_cert = footer->has_fast_final_cert || footer->has_final_cert;
  if( FD_UNLIKELY( (err=option_ser( has_block_final_cert, &buf, &rem )) ) ) return err;
  if( has_block_final_cert ) {
    if( FD_UNLIKELY( (err=block_final_cert_ser( footer, &buf, &rem )) ) ) return err;
  }

  if( FD_UNLIKELY( (err=option_ser( footer->has_skip_reward_cert, &buf, &rem )) ) ) return err;
  if( footer->has_skip_reward_cert ) {
    if( FD_UNLIKELY( (err=reward_cert_ser( &footer->skip_reward_cert, 0, &buf, &rem )) ) ) return err;
  }

  if( FD_UNLIKELY( (err=option_ser( footer->has_notar_reward_cert, &buf, &rem )) ) ) return err;
  if( footer->has_notar_reward_cert ) {
    if( FD_UNLIKELY( (err=reward_cert_ser( &footer->notar_reward_cert, 1, &buf, &rem )) ) ) return err;
  }

  *_buf = buf; *_rem = rem;
  return FD_BLOCK_MARKER_SER_SUCCESS;
}

int
fd_block_marker_ser( fd_block_marker_t const * marker,
                     uchar *                   buf,
                     ulong                     buf_max,
                     ulong *                   buf_sz ) {
  ulong rem = buf_max;
  int   err;

  if( FD_UNLIKELY( marker->variant!=HEADER && marker->variant!=FOOTER ) ) return FD_BLOCK_MARKER_SER_ERR_UNSUPPORTED;

  CHECK_SPACE( sizeof(fd_block_marker_serde_t) );
  fd_block_marker_serde_t * out = (fd_block_marker_serde_t *)buf;
  out->entry_cnt = 0UL;
  out->version   = (ushort)1;
  out->variant   = marker->variant;
  ADVANCE( sizeof(fd_block_marker_serde_t) );

  uchar * payload = buf;
  if( marker->variant==HEADER ) err = block_header_ser( &marker->header, &buf, &rem );
  else                          err = block_footer_ser( &marker->footer, &buf, &rem );
  if( FD_UNLIKELY( err ) ) return err;

  /* The length is only known once the payload is written. */
  out->length = (ushort)(buf-payload);

  if( buf_sz ) *buf_sz = buf_max-rem;
  return FD_BLOCK_MARKER_SER_SUCCESS;
}
