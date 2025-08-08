#include "fd_contact_info.h"
#include "fd_gossip_private.h"
#include "../../util/bits/fd_bits.h"

#define SER_INIT( payload, payload_sz, offset ) \
  uchar *       _payload    = (payload);        \
  ushort const  _offset     = (offset);         \
  ushort        _i          = (offset);         \
  ulong const   _payload_sz = (payload_sz);     \
  (void)        _offset;                        \
  (void)        _payload_sz;

#define INC( n ) (_i += (ushort)(n))

#define CUR_OFFSET      (_i)
#define CURSOR          (_payload+_i)
#define BYTES_CONSUMED  (_i-_offset)
#define BYTES_REMAINING (_payload_sz-_i)

int 
fd_gossip_pull_request_init( uchar *       payload,
                             ulong         payload_sz,
                             ulong         num_keys,
                             ulong         bloom_bits_cnt,
                             ulong         mask,
                             uint          mask_bits,
                             uchar const * contact_info_crds,
                             ulong         contact_info_crds_sz,
                             ulong **      out_bloom_keys,
                             ulong **      out_bloom_bits,
                             ulong **      out_bits_set,
                             ulong *       out_payload_sz ){
  SER_INIT( payload, payload_sz, 0U );
  FD_STORE( uint, CURSOR, FD_GOSSIP_MESSAGE_PULL_REQUEST );  INC(          4U );
  FD_STORE( ulong, CURSOR, num_keys                       ); INC(          8U );
  *out_bloom_keys = (ulong *)( CURSOR );                     INC( num_keys*8U );

  if( FD_LIKELY( !!bloom_bits_cnt ) ) {
    /* Bloom bits is a bitvec<u64>, so we need to be careful about converting bloom bits count to vector lengths */
    ulong bloom_vec_len = (bloom_bits_cnt+63UL)/64UL;
    FD_STORE( uchar, CURSOR, 1 )            ; INC(               1U ); /* has_bits */
    FD_STORE( ulong, CURSOR, bloom_vec_len ); INC(               8U );
    *out_bloom_bits = (ulong *)( CURSOR )   ; INC( bloom_vec_len*8U );
  } else {
    FD_STORE( uchar, CURSOR, 0 ); INC( 1U ); /* has_bits */
    *out_bloom_bits = NULL;
  }
  FD_STORE( ulong, CURSOR, bloom_bits_cnt ); INC( 8U );
  *out_bits_set = (ulong *)(CURSOR)        ; INC( 8U );

  FD_STORE( ulong, CURSOR, mask      )     ; INC( 8U );
  FD_STORE( uint,  CURSOR, mask_bits )     ; INC( 4U );

  if( FD_UNLIKELY( BYTES_REMAINING<contact_info_crds_sz )) {
    FD_LOG_WARNING(( "Not enough space in pull request for contact info, check bloom filter params" ));
    return -1;
  }
  fd_memcpy( CURSOR, contact_info_crds, contact_info_crds_sz );
  INC( contact_info_crds_sz );
  *out_payload_sz = BYTES_CONSUMED;
  return 0;
}

static inline ushort
varint_encode( ulong u64, uchar * out_buf ) {
  ushort i = 0UL;
  do {
    uchar byte = (uchar)(u64 & 0x7FUL);
    u64 >>= 7UL;
    if( u64 ) byte |= 0x80U;
    FD_STORE( uchar, out_buf+i, byte );
    i++;
  } while( u64 );
  return i;
}

static inline ulong
encode_version( fd_contact_info_t const * contact_info,
                uchar *                   out_buf,
                ulong                     out_buf_sz,
                ushort                    start_offset ) {
  SER_INIT( out_buf, out_buf_sz, start_offset );

  INC( varint_encode( contact_info->version.major, CURSOR ) );
  INC( varint_encode( contact_info->version.minor, CURSOR ) );
  INC( varint_encode( contact_info->version.patch, CURSOR ) );

  FD_STORE( uint, CURSOR, contact_info->version.commit )           ; INC( 4U );

  FD_STORE( uint, CURSOR, contact_info->version.feature_set )      ; INC( 4U );

  INC( varint_encode( contact_info->version.client, CURSOR ) );

  return BYTES_CONSUMED;
}

int
fd_gossip_contact_info_encode( fd_contact_info_t const *     contact_info,
                               uchar *                       out_buf,
                               ulong                         out_buf_sz,
                               ulong *                       opt_encoded_sz ) {
  SER_INIT( out_buf, out_buf_sz, 0U );

  INC( 64U ); /* Reserve space for signature */

  FD_STORE( uint, CURSOR, FD_GOSSIP_VALUE_CONTACT_INFO ) ; INC(  4U );
  fd_memcpy( CURSOR, contact_info->pubkey.uc, 32UL )        ; INC( 32U );

  ulong wallclock = (ulong)FD_NANOSEC_TO_MILLI( contact_info->wallclock_nanos );
  INC( varint_encode( wallclock, CURSOR ) );

  ulong instance_creation_wallclock = (ulong)FD_NANOSEC_TO_MILLI( contact_info->instance_creation_wallclock_nanos );
  FD_STORE( ulong,  CURSOR, instance_creation_wallclock ); INC( 8UL );
  FD_STORE( ushort, CURSOR, contact_info->shred_version ); INC( 2UL );

  INC( encode_version( contact_info, out_buf, out_buf_sz, CUR_OFFSET ) );

  /* fd_contact_info_t has a fixed-size array of addresses and sockets, while
     the encoded representation is a variable-length array of addrs and
     sockets, where sockets are sorted by port offsets and index into addrs
     to specify address.

     TODO: This is awkwardly placed. Caller should be in charge of setting these
     data structures, leaving encode with the sole role of serializing them to
     bytes. */
  uint                                  addrs[ FD_CONTACT_INFO_SOCKET_MAX ];
  uchar                                 addrs_cnt;
  fd_gossip_contact_info_socket_entry_t socket_entries[ FD_CONTACT_INFO_SOCKET_MAX ];
  uchar                                 socket_entries_cnt;

  if( FD_UNLIKELY( fd_contact_info_convert_sockets( contact_info, socket_entries, &socket_entries_cnt, addrs, &addrs_cnt ) ) ) {
    FD_LOG_ERR(( "Failed to convert contact info sockets, check arguments to fd_contact_info_convert_sockets" ));
    return -1;
  }

  /* Encode addrs and socket entries. Properties exploited:
     - length of either array never exceeds FD_GOSSIP_SOCKET_TAG_MAX, which
       is 13 < 2^7. This means we can assume the length is always encoded as
       a single byte varint */
  FD_STORE( uchar, CURSOR, addrs_cnt )                           ; INC( 1UL );
  for( ulong j=0UL; j<addrs_cnt; j++ ) {
    /* Each address is 8 bytes including discriminant */
    FD_STORE( uint, CURSOR, 0U )                                 ; INC( 4UL ); /* Enum discriminant */
    FD_STORE( uint, CURSOR, addrs[j] )                           ; INC( 4UL );
  }

  FD_STORE( uchar, CURSOR, socket_entries_cnt )                  ; INC( 1UL );

  for( ulong j=0UL; j<socket_entries_cnt; j++ ) {
    FD_STORE( uchar, CURSOR, socket_entries[j].tag )             ; INC( 1UL );
    FD_STORE( uchar, CURSOR, socket_entries[j].addr_index )      ; INC( 1UL );

    INC( varint_encode( socket_entries[j].port_offset, CURSOR ) );
  }

  /* No extensions for now, but because of a quirk in short_vec we need to encode
     the length (which is 0) */
  FD_STORE( uchar, CURSOR, 0U )                                  ; INC( 1UL );

  if( opt_encoded_sz ) {
    *opt_encoded_sz = BYTES_CONSUMED;
  }
  return 0;
}

int
fd_gossip_crds_vote_encode( uchar *       out_buf,
                            ulong         out_buf_sz,
                            uchar const * txn,
                            ulong         txn_sz,
                            uchar const * identity_pubkey,
                            long          now,
                            ulong *       opt_encoded_sz ) {
  SER_INIT( out_buf, out_buf_sz, 0U );
  INC( 64U ); /* Reserve space for signature */

  FD_STORE( uint,  CURSOR, FD_GOSSIP_VALUE_VOTE )             ; INC( 4U );
  FD_STORE( uchar, CURSOR, 0U )                               ; INC( 1U ); /* TODO: vote tower index, unused for now */
  fd_memcpy( CURSOR, identity_pubkey, 32UL )                  ; INC( 32U );
  fd_memcpy( CURSOR, txn,             txn_sz )                ; INC( (ushort)txn_sz );
  FD_STORE( ulong, CURSOR, (ulong)FD_NANOSEC_TO_MILLI( now ) ); INC( 8U );

  if( opt_encoded_sz ) {
    *opt_encoded_sz = BYTES_CONSUMED; /* Return the size of the encoded vote */
  }
  return 0;
}
