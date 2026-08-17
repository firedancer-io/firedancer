#include "fd_block_marker.h"

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
    int   is_fast = ag_cert_block_final_de( &footer->fast_final_cert, &footer->final_cert, &footer->notar_cert, buf, rem, &consumed );
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
