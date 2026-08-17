#include "fd_block_marker.h"

#include "../../ballet/txn/fd_compact_u16.h"      /* reward cert bitmaps are ShortU16 length prefixed */
#include "../../choreo/votor/ag_bls.h"         /* for AG_BLS_PUB_COMPRESSED_SZ */

/* Cursor helpers.  buf/rem track the unconsumed input; each helper
   either advances past a well-formed sub-encoding or returns the
   FD_BLOCK_MARKER_DE_ERR_* it failed with. */

#define CHECK_LEFT( n ) do {                                   \
  if( FD_UNLIKELY( (n)>rem ) ) return FD_BLOCK_MARKER_DE_ERR_TRUNCATED; \
} while( 0 )

#define ADVANCE( n ) do { buf += (n); rem -= (n); } while( 0 )

/* option_de reads a Option tag (u8, 0 or 1). */

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

/* votes_aggregate_skip advances past a VotesAggregate:

     compressed BLS signature (96) | bitmap byte count (u16 LE) | bitmap */

static int
votes_aggregate_skip( uchar const ** _buf,
                      ulong *        _rem ) {
  uchar const * buf = *_buf;
  ulong         rem = *_rem;
  CHECK_LEFT( AG_BLS_SIG_COMPRESSED_SZ+2UL );
  ulong bitmap_sz = (ulong)FD_LOAD( ushort, buf+AG_BLS_SIG_COMPRESSED_SZ );
  ADVANCE( AG_BLS_SIG_COMPRESSED_SZ+2UL );
  CHECK_LEFT( bitmap_sz );
  ADVANCE( bitmap_sz );
  *_buf = buf; *_rem = rem;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

/* block_final_cert_skip advances past a BlockFinalizationCert:

     slot (8) | block_id (32) | final_aggregate (VotesAggregate) |
     has_notar_aggregate (1) | [notar_aggregate (VotesAggregate)] */

static int
block_final_cert_skip( uchar const ** _buf,
                       ulong *        _rem ) {
  uchar const * buf = *_buf;
  ulong         rem = *_rem;
  CHECK_LEFT( 8UL+sizeof(fd_hash_t) );
  ADVANCE( 8UL+sizeof(fd_hash_t) );

  int err;
  if( FD_UNLIKELY( (err=votes_aggregate_skip( &buf, &rem )) ) ) return err;

  int has_notar;
  if( FD_UNLIKELY( (err=option_de( &buf, &rem, &has_notar )) ) ) return err;
  if( has_notar ) {
    if( FD_UNLIKELY( (err=votes_aggregate_skip( &buf, &rem )) ) ) return err;
  }

  *_buf = buf; *_rem = rem;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

/* reward_cert_skip advances past a SkipRewardCertificate
   (block_id_sz==0) or a NotarRewardCertificate
   (block_id_sz==sizeof(fd_hash_t)):

     slot (8) | [block_id (32)] | compressed BLS signature (96) |
     bitmap byte count (ShortU16) | bitmap */

static int
reward_cert_skip( uchar const ** _buf,
                  ulong *        _rem,
                  ulong          block_id_sz ) {
  uchar const * buf = *_buf;
  ulong         rem = *_rem;
  CHECK_LEFT( 8UL+block_id_sz+AG_BLS_SIG_COMPRESSED_SZ );
  ADVANCE( 8UL+block_id_sz+AG_BLS_SIG_COMPRESSED_SZ );

  ulong cu16_sz = fd_cu16_dec_sz( buf, rem );
  if( FD_UNLIKELY( !cu16_sz ) ) return FD_BLOCK_MARKER_DE_ERR_MALFORMED;
  ulong bitmap_sz = (ulong)fd_cu16_dec_fixed( buf, cu16_sz );
  ADVANCE( cu16_sz );
  CHECK_LEFT( bitmap_sz );
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

  footer->final_cert        = NULL; footer->final_cert_sz        = 0UL;
  footer->skip_reward_cert  = NULL; footer->skip_reward_cert_sz  = 0UL;
  footer->notar_reward_cert = NULL; footer->notar_reward_cert_sz = 0UL;

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
    uchar const * cert = buf;
    if( FD_UNLIKELY( (err=block_final_cert_skip( &buf, &rem )) ) ) return err;
    footer->final_cert    = cert;
    footer->final_cert_sz = (ulong)(buf-cert);
  }

  if( FD_UNLIKELY( (err=option_de( &buf, &rem, &present )) ) ) return err;
  if( present ) {
    uchar const * cert = buf;
    if( FD_UNLIKELY( (err=reward_cert_skip( &buf, &rem, 0UL )) ) ) return err;
    footer->skip_reward_cert    = cert;
    footer->skip_reward_cert_sz = (ulong)(buf-cert);
  }

  if( FD_UNLIKELY( (err=option_de( &buf, &rem, &present )) ) ) return err;
  if( present ) {
    uchar const * cert = buf;
    if( FD_UNLIKELY( (err=reward_cert_skip( &buf, &rem, sizeof(fd_hash_t) )) ) ) return err;
    footer->notar_reward_cert    = cert;
    footer->notar_reward_cert_sz = (ulong)(buf-cert);
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

  /* Decode the length-prefixed payload.  The payload deserializer may
     consume less than length: unknown fields appended are skipped
     rather than treated as malformed. */

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
