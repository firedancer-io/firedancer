#include "fd_gossip_types.h"
#include "fd_gossip_private.h"
#include "../../util/bits/fd_bits.h"

#define SER_INIT( payload, payload_sz, offset ) \
  uchar *       _payload    = (payload);        \
  ulong const   _offset     = (offset);         \
  ulong         _i          = (offset);         \
  ulong const   _payload_sz = (payload_sz);     \
  (void)        _offset;                        \
  (void)        _payload_sz;

#define INC( n ) (_i += (ulong)(n))

#define CUR_OFFSET      ((ushort)_i)
#define CURSOR          (_payload+_i)
#define BYTES_CONSUMED  (_i-_offset)
#define BYTES_REMAINING (_payload_sz-_i)

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

/* The Gossip encoding of a contact info splits the sockets into
   two vectors: socket entries (socket_entry_t) and addrs (uint).
   The sockets are ordered by port values, and the port values
   are encoded as "offsets" to the previous socket entry's value.
   addrs is a list of unique IP addresses, and a socket entry's
   addr_index indexes into this list. To illustrate the conversion:

   sockets = [
      { IP: 192.1.1.1, Port: 1000 },  # tag gossip
      {     192.1.2.1,       2000 },  # tag serve_repair_quic
      {     0,               0 },     # NULL socket entry for tag RPC
      {     192.1.1.1,       500 }    # tag rpc pubsub
  ]

  would be transformed to:

  addrs = [
    192.1.1.1,
    192.1.2.1
  ]

  socket_entries = [
    { port_offset: 500,  tag: 3, addr_index: 1 }, # first entry's port_offset is the actual port value
    {              500,       0,             0 }, # second entry is relative to the first entry's port value
    {              1000,      1,             0 }  # third entry is relative to the second entry's port value
                                                  # null socket entry is not included
  ]
*/
struct socket_entry {
  ushort port_offset;
  uchar  tag;
  uchar  addr_index;
};

typedef struct socket_entry socket_entry_t;

struct socket_ctx {
  fd_ip4_port_t socket;
  uchar         socket_tag;
};

typedef struct socket_ctx socket_ctx_t;

#define SORT_NAME           sort_socket_port
#define SORT_KEY_T          socket_ctx_t
#define SORT_BEFORE( a, b ) ( (a).socket.port<(b).socket.port )

#include "../../util/tmpl/fd_sort.c"

#define FD_CONTACT_INFO_SOCKET_MAX FD_CONTACT_INFO_SOCKET_CNT


static inline int
contact_info_convert_sockets( fd_contact_info_t const *             contact_info,
                              socket_entry_t                        out_sockets_entries[ static FD_CONTACT_INFO_SOCKET_MAX ],
                              uchar *                               out_socket_entries_cnt,
                              uint                                  out_addrs[ static FD_CONTACT_INFO_SOCKET_MAX ],
                              uchar *                               out_addrs_cnt ) {
  if( FD_UNLIKELY( !contact_info || !out_socket_entries_cnt || !out_addrs_cnt ) ) {
    FD_LOG_WARNING(( "Invalid arguments to fd_contact_info_convert_sockets" ));
    return -1;
  }

  socket_ctx_t filled_up[ FD_CONTACT_INFO_SOCKET_MAX ];
  ulong filled_up_cnt = 0UL;
  for( ulong j=0; j<FD_CONTACT_INFO_SOCKET_MAX; j++ ) {
    if( contact_info->sockets[j].l!=0 ){
      filled_up[filled_up_cnt].socket = contact_info->sockets[j];
      /* Convert port to host order. Needed for sorting and because port info
         is encoded in host order in ContactInfo */
      filled_up[filled_up_cnt].socket.port = fd_ushort_bswap( filled_up[filled_up_cnt].socket.port );
      filled_up[filled_up_cnt].socket_tag = (uchar)j;
      filled_up_cnt++;
    }
  }

  socket_ctx_t scratch[ FD_CONTACT_INFO_SOCKET_MAX ];
  socket_ctx_t * sorted = sort_socket_port_stable_fast( filled_up, filled_up_cnt, scratch );

  uchar addrs_cnt = 0UL;
  uchar socket_entries_cnt = 0UL;

  /* fill in first entry */
  out_addrs[addrs_cnt++]                              = sorted[0].socket.addr;
  out_sockets_entries[socket_entries_cnt].port_offset = sorted[0].socket.port;
  out_sockets_entries[socket_entries_cnt].addr_index  = 0U;
  out_sockets_entries[socket_entries_cnt++].tag       = sorted[0].socket_tag;

  for( ulong j=1; j<filled_up_cnt; j++ ) {
    socket_ctx_t const * socket = &sorted[j];

    uchar addr_found = 0U;
    for( ulong k=0UL; k<addrs_cnt; k++ ) {
      if( out_addrs[k]==socket->socket.addr ) {
        /* Already have this address, set index */
        out_sockets_entries[socket_entries_cnt].addr_index = (uchar)k;
        addr_found                                         = 1U;
        break;
      }
    }
    if( !addr_found ) {
      /* New address, add it */
      out_addrs[addrs_cnt++]                              = socket->socket.addr;
      out_sockets_entries[socket_entries_cnt].addr_index  = (uchar)(addrs_cnt-1);
    }

    out_sockets_entries[socket_entries_cnt].port_offset   = (ushort)(socket->socket.port-sorted[j-1].socket.port);
    out_sockets_entries[socket_entries_cnt++].tag         = socket->socket_tag;
  }

  *out_addrs_cnt              = addrs_cnt;
  *out_socket_entries_cnt     = socket_entries_cnt;
  return 0;
}




int
fd_gossip_pull_request_init( uchar *       payload,
                             ulong         payload_sz,
                             ulong         num_keys,
                             ulong         num_bits,
                             ulong         mask,
                             uint          mask_bits,
                             uchar const * contact_info_crds,
                             ulong         contact_info_crds_sz,
                             ulong **      out_bloom_keys,
                             ulong **      out_bloom_bits,
                             ulong **      out_bits_set,
                             ulong *       out_payload_sz ) {
  FD_TEST( payload_sz<=FD_GOSSIP_MTU );
  SER_INIT( payload, payload_sz, 0U );
  FD_STORE( uint, CURSOR, FD_GOSSIP_MESSAGE_PULL_REQUEST ); INC(          4U );
  FD_STORE( ulong, CURSOR, num_keys                      ); INC(          8U );
  *out_bloom_keys = (ulong *)( CURSOR )                   ; INC( num_keys*8U );

  if( FD_LIKELY( !!num_bits ) ) {
    /* Bloom bits is a bitvec<u64>, so we need to be careful about converting bloom bits count to vector lengths */
    ulong bloom_vec_len = (num_bits+63UL)/64UL;
    FD_STORE( uchar, CURSOR, 1 )            ; INC(               1U ); /* has_bits */
    FD_STORE( ulong, CURSOR, bloom_vec_len ); INC(               8U );
    *out_bloom_bits = (ulong *)( CURSOR )   ; INC( bloom_vec_len*8U );
  } else {
    FD_STORE( uchar, CURSOR, 0 ); INC( 1U ); /* has_bits */
    *out_bloom_bits = NULL;
  }
  FD_STORE( ulong, CURSOR, num_bits ); INC( 8U );
  *out_bits_set = (ulong *)(CURSOR)  ; INC( 8U );

  FD_STORE( ulong, CURSOR, mask      ); INC( 8U );
  FD_STORE( uint,  CURSOR, mask_bits ); INC( 4U );

  if( FD_UNLIKELY( BYTES_REMAINING<contact_info_crds_sz )) {
    FD_LOG_WARNING(( "Not enough space in pull request for contact info, check bloom filter params" ));
    return -1;
  }
  fd_memcpy( CURSOR, contact_info_crds, contact_info_crds_sz );
  INC( contact_info_crds_sz );
  *out_payload_sz = BYTES_CONSUMED;
  return 0;
}

int
fd_gossip_contact_info_encode( fd_contact_info_t const *     contact_info,
                               uchar *                       out_buf,
                               ulong                         out_buf_sz,
                               ulong *                       opt_encoded_sz ) {
  FD_TEST( out_buf_sz<=FD_GOSSIP_MTU );
  /* fd_contact_info_t has a fixed-size array of addresses and sockets, while
     the encoded representation is a variable-length array of addrs and
     sockets, where sockets are sorted by port offsets and index into addrs
     to specify address. */
  uint           addrs[ FD_CONTACT_INFO_SOCKET_MAX ];
  uchar          addrs_cnt;
  socket_entry_t socket_entries[ FD_CONTACT_INFO_SOCKET_MAX ];
  uchar          socket_entries_cnt;

  if( FD_UNLIKELY( contact_info_convert_sockets( contact_info, socket_entries, &socket_entries_cnt, addrs, &addrs_cnt ) ) ) {
    FD_LOG_ERR(( "Failed to convert contact info sockets, check arguments to fd_contact_info_convert_sockets" ));
  }

  SER_INIT( out_buf, out_buf_sz, 0U );

  INC( 64U ); /* Reserve space for signature */

  FD_STORE( uint, CURSOR, FD_GOSSIP_VALUE_CONTACT_INFO ) ; INC(  4U );
  fd_memcpy( CURSOR, contact_info->pubkey.uc, 32UL )        ; INC( 32U );

  ulong wallclock = (ulong)FD_NANOSEC_TO_MILLI( contact_info->wallclock_nanos );
  INC( varint_encode( wallclock, CURSOR ) );

  ulong instance_creation_wallclock = (ulong)FD_NANOSEC_TO_MICRO( contact_info->instance_creation_wallclock_nanos );
  FD_STORE( ulong,  CURSOR, instance_creation_wallclock ); INC( 8UL );
  FD_STORE( ushort, CURSOR, contact_info->shred_version ); INC( 2UL );

  INC( encode_version( contact_info, out_buf, out_buf_sz, CUR_OFFSET ) );

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
