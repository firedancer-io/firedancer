#define _GNU_SOURCE /* memmem */
#include <errno.h>
#include <stdio.h> /* fputs, fprintf */
#include <stdlib.h> /* aligned_alloc */
#include <unistd.h> /* pread */

#include "fd_quic.h"
#include "../../ballet/hex/fd_hex.h"
#include "../../waltz/quic/fd_quic_proto.h"
#include "../../waltz/quic/fd_quic_proto.c"
#include "../../waltz/quic/templ/fd_quic_parse_util.h"
#include "../../util/net/fd_pcap.h"
#include "../../util/net/fd_pcapng.h"
#include "../../util/net/fd_pcapng_private.h" /* FIXME */
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"

#define MAX_KEYS_DEFAULT 1024

static void
usage_short( void ) {
  fputs( "Usage: fd_quic_pcap [COMMAND] [FLAGS] {FILE.PCAPNG}\n", stderr );
}

static void
usage( void ) {
  usage_short();
  /* FIXME uncomment when tool is ready
  fprintf( stderr,
    "\n"
    "Tool to analyze Solana network QUIC traffic captures.\n"
    "\n"
    "Supported file formats: tcpdump pcap (little endian) and pcap-ng\n"
    "Supported pcap-ng blocks: SPB, EPB, DSB (inline TLS keys)\n"
    "Supported cipher suites: TLS_AES_128_GCM_SHA256\n"
    "Supported link layers: Ethernet, Linux SLL\n"
    "Assumes that conn IDs are 8 bytes long.\n"
    "\n"
    "Commands:\n"
    "  tpu-stat       Print Solana TPU traffic statistics\n"
    "  tpu-peer-stat  Print Solana TPU traffic per-peer statistics\n"
    "  tpu-trace      Trace Solana TPU traffic metadata to CSV format\n"
    "\n"
    "Optional flags:\n"
    // TODO "  --key-file   Path to TLS key log txt file (SSKEYLOGFILE format)\n"
    "  --key-max    Max concurrent TLS key count (default " FD_STRINGIFY( MAX_KEYS_DEFAULT ) ")\n"
    "\n" );
  */
}

static void
usage_invalid( void ) {
  fputs( "Invalid arguments!\n", stderr );
  usage_short();
}

static void
reject_unknown_flags( int *    pargc,
                      char *** pargv ) {
  int expect_flag = 1;
  int new_argc = 0;
  int arg;
  for( arg=0; arg<(*pargc); arg++ ) {
    if( !expect_flag || 0!=strncmp( (*pargv)[arg], "--", 2 ) ) {
      (*pargv)[new_argc++] = (*pargv)[arg];
    } else if( (++arg)<(*pargc) ) {
      if( (*pargv)[arg][2] == '0' ) {
        expect_flag = 0;
      } else {
        FD_LOG_ERR(( "Unsupported flag: %s", (*pargv)[arg] ));
      }
    }
  }
}

/* Helper for maps with 32 byte keys */

union key32 {
  uchar key[32];
  ulong ul[4];
};
typedef union key32 key32_t;

static ulong map_seed;
__attribute__((constructor)) static void random_seeds( void ) {
  if( FD_UNLIKELY( !fd_rng_secure( &map_seed, sizeof(map_seed) ) ) ) {
    FD_LOG_WARNING(( "fd_rng_secure failed" ));
  }
}

/* Declare a map resolving Client Random => encryption keys */

struct key_map {
  key32_t client_random;
  /* FIXME support a ring buffer of multiple keys */
  uchar server_app_secret[32];
  uchar client_app_secret[32];
};

typedef struct key_map key_map_t;

#define MAP_NAME              key_map
#define MAP_T                 key_map_t
#define MAP_HASH_T            ulong
#define MAP_KEY               client_random
#define MAP_KEY_T             key32_t
#define MAP_KEY_NULL          ((key32_t){.ul={0,0,0,0}})
#define MAP_KEY_EQUAL(k0,k1)  (0==memcmp((k0).key,(k1).key,32))
#define MAP_KEY_EQUAL_IS_SLOW 0
#define MAP_KEY_HASH(key)     fd_hash( map_seed, key.key, 32 )
#define MAP_KEY_INVAL(k)      ((0==k.ul[0]) & (0==k.ul[1]) & (0==k.ul[2]) & (0==k.ul[3]))
#define MAP_MEMOIZE           0
#include "../../util/tmpl/fd_map_dynamic.c"

/* Declare a map resolving conn ID => Client Random */

struct conn_map {
  ulong conn_id;
  uchar client_random[32];
};

typedef struct conn_map conn_map_t;

#define MAP_NAME    conn_map
#define MAP_T       conn_map_t
#define MAP_KEY     conn_id
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"


struct quic_pcap_params {
  char const * pcap_path;
  ulong        key_max;
};

typedef struct quic_pcap_params quic_pcap_params_t;

struct quic_pcap_iter {
  FILE *       pcap_file;
  conn_map_t * conn_map;
  key_map_t *  key_map;
  ulong        key_max;
  ulong        key_cnt;
  ulong        key_ignore_cnt;
};

typedef struct quic_pcap_iter quic_pcap_iter_t;

static quic_pcap_iter_t *
quic_pcap_iter_new( quic_pcap_iter_t *         iter,
                    quic_pcap_params_t const * params ) {
  int lg_slot_cnt = fd_ulong_find_msb_w_default( fd_ulong_pow2_up( params->key_max*4 ), 0 );

  void * key_map_mem = aligned_alloc( key_map_align(), key_map_footprint( lg_slot_cnt ) );
  key_map_t * key_map = key_map_join( key_map_new( key_map_mem, lg_slot_cnt ) );
  if( FD_UNLIKELY( !key_map ) ) FD_LOG_ERR(( "key_map alloc failed" ));

  void * conn_map_mem = aligned_alloc( conn_map_align(), conn_map_footprint( lg_slot_cnt ) );
  conn_map_t * conn_map = conn_map_join( conn_map_new( conn_map_mem, lg_slot_cnt ) );
  if( FD_UNLIKELY( !conn_map ) ) FD_LOG_ERR(( "conn_map alloc failed" ));

  FILE * pcap_file = fopen( params->pcap_path, "rb" );
  if( FD_UNLIKELY( !pcap_file ) ) {
    FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", params->pcap_path, errno, fd_io_strerror( errno ) ));
  }

  *iter = (quic_pcap_iter_t) {
    .pcap_file = pcap_file,
    .conn_map  = conn_map,
    .key_map   = key_map,
    .key_max   = params->key_max
  };
  return iter;
}

static void
quic_pcap_iter_add_one_key( quic_pcap_iter_t * iter,
                            char const *       str,
                            ulong              str_sz ) {

  /* Silently ignore tiny lines, those are probably just whitespace */
  if( str_sz<6 ) return;

  /* Copy into mutable buffer */
  char line[ 512 ];
  if( FD_UNLIKELY( str_sz>=sizeof(line) ) ) {
    FD_LOG_WARNING(( "Ignoring oversz TLS key log line" ));
    FD_LOG_HEXDUMP_DEBUG(( "Oversz TLS key log line", str, str_sz ));
    return;
  }
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( line ), str, str_sz ) );

  /* Tokenize */
  char * tokens[3];
  ulong tok_cnt = fd_cstr_tokenize( tokens, 3, line, ' ' );
  if( FD_UNLIKELY( tok_cnt!=3 ) ) {
    FD_LOG_WARNING(( "Ignoring malformed TLS key log line" ));
    FD_LOG_HEXDUMP_DEBUG(( "Malformed TLS key log line", str, str_sz ));
    return;
  }

  /* Parse client random */
  if( FD_UNLIKELY( strlen( tokens[1] )!=64UL ) ) {
    FD_LOG_WARNING(( "Ignoring odd sized client random in TLS key log" ));
    return;
  }
  key32_t client_random;
  if( FD_UNLIKELY( fd_hex_decode( client_random.key, tokens[1], 32UL )!=32UL ) ) {
    FD_LOG_WARNING(( "Ignoring malformed client random in TLS key log" ));
    return;
  }

  /* Parse encryption key */
  if( FD_UNLIKELY( strlen( tokens[2] )!=64UL ) ) {
    FD_LOG_WARNING(( "Ignoring odd sized encryption key in TLS key log" ));
    return;
  }
  uchar encryption_key[32];
  if( FD_UNLIKELY( fd_hex_decode( encryption_key, tokens[2], 32UL )!=32UL ) ) {
    FD_LOG_WARNING(( "Ignoring malformed encryption key in TLS key log" ));
    return;
  }

  /* Upsert record */
  key_map_t * record = key_map_query( iter->key_map, client_random, NULL );
  if( !record ) {
    if( FD_UNLIKELY( key_map_key_cnt( iter->key_map ) >= iter->key_max ) ) {
      iter->key_ignore_cnt++;
      static int warned = 0;
      if( !warned ) {
        FD_LOG_WARNING(( "Reached TLS key limit (%lu), ignoring new connections", iter->key_max ));
        warned = 1;
      }
      return;
    }
    record = key_map_insert( iter->key_map, client_random );
    *record = (key_map_t) { .client_random = client_random };
  }

  /* Extract decryption key
     For now, ignore handshake keys */
  if( strncmp( tokens[0], "CLIENT_TRAFFIC_SECRET_", 22UL ) ||
      strncmp( tokens[0], "SERVER_TRAFFIC_SECRET_", 22UL ) ) {

    int   is_client = ( tokens[0][0] == 'C' );
    ulong key_idx   = fd_cstr_to_ulong( tokens[0] + 22UL );
    if( key_idx!=0 ) {
      iter->key_ignore_cnt++;
      FD_LOG_DEBUG(( "Ignoring key rotation" ));
      return;
    }

    uchar * dst = ( is_client ? record->client_app_secret : record->server_app_secret );
    memcpy( dst, encryption_key, 32 );
    iter->key_cnt++;

  } else {
    iter->key_ignore_cnt++;
  }

}

static void
quic_pcap_iter_add_keys( quic_pcap_iter_t * iter,
                         char const *       str,
                         ulong              str_sz ) {
  while( str_sz ) {
    char const * crlf = memmem( str, str_sz, "\r\n", 2UL );
    char const * lf   = memchr( str, '\n', str_sz );
    char const * eol  = ( crlf ? crlf+2 : ( lf ? lf+1 : str+str_sz ) );
    quic_pcap_iter_add_one_key( iter, str, str_sz );
    str_sz -= (ulong)( eol - str );
  }
}

static void
quic_pcap_iter_deliver_initial(
    quic_pcap_iter_t *  iter,
    uint                ip4_saddr,
    uchar *             data,
    ulong               data_sz,
    ulong *             out_pkt_sz
) {
  (void)iter;
  (void)ip4_saddr;
  (void)out_pkt_sz;

  fd_quic_initial_t initial[1];
  ulong rc = fd_quic_decode_initial( initial, data, data_sz );
  if( FD_UNLIKELY( rc==FD_QUIC_PARSE_FAIL ) ) return;
  ulong pnoff  = initial->pkt_num_pnoff;
  ulong tot_sz = pnoff + initial->len;
  if( FD_UNLIKELY( tot_sz>data_sz ) ) return;
  *out_pkt_sz = tot_sz;
  data_sz     = tot_sz;

  fd_quic_crypto_secrets_t secrets[1];
  fd_quic_gen_initial_secret( secrets, initial->dst_conn_id, initial->dst_conn_id_len );
  fd_quic_gen_secrets( secrets, fd_quic_enc_level_initial_id );

  fd_quic_crypto_keys_t keys[1];
  fd_quic_gen_keys( keys, secrets->secret[ fd_quic_enc_level_initial_id ][ 0 ] );

  /* Undo initial packet protection */
  /* FIXME does this support QUIC retries? */

  if( FD_UNLIKELY(
        fd_quic_crypto_decrypt_hdr( data, tot_sz, pnoff, keys )
        != FD_QUIC_SUCCESS ) ) {
    FD_LOG_WARNING(( "Failed to decrypt initial" ));
    return;
  }

  uint  pkt_number_sz = fd_quic_h0_pkt_num_len( data[0] ) + 1u;
  ulong pkt_number    = fd_quic_pktnum_decode( data+pnoff, pkt_number_sz );

  if( FD_UNLIKELY(
        fd_quic_crypto_decrypt( data, tot_sz, pnoff, pkt_number, keys )
        != FD_QUIC_SUCCESS ) ) {
    FD_LOG_WARNING(( "Failed to decrypt initial" ));
    return;
  }

  /* Expect first frame to be a CRYPTO frame */

  data    += (rc+pkt_number_sz);
  data_sz -= (rc+pkt_number_sz);
  if( FD_UNLIKELY( data_sz<1 ) ) return;
  if( data[0]!=0x06 ) return;

  fd_quic_crypto_frame_t crypto[1];
  rc = fd_quic_decode_crypto_frame( crypto, data, data_sz );
  if( FD_UNLIKELY( rc==FD_QUIC_PARSE_FAIL ) ) return;
  data    += rc;
  data_sz -= rc;
  ulong left = fd_ulong_min( crypto->length, data_sz );

  /* Expect first TLS message to be a ClientHello */

  if( FD_UNLIKELY( left < 6+32 ) ) return;
  if( data[0] != 0x01 ) return; /* ClientHello */
  uchar const * client_random = data + 6;
  FD_LOG_HEXDUMP_WARNING(( "ClientRandom", client_random, 32 ));

}

static void
quic_pcap_iter_deliver_handshake(
    quic_pcap_iter_t *  iter,
    uint                ip4_saddr,
    uchar const * const data,
    ulong               data_sz,
    ulong *             out_pkt_sz
) {
  (void)iter;
  (void)ip4_saddr;
  (void)data;
  (void)data_sz;
  (void)out_pkt_sz;
}

static void
quic_pcap_iter_deliver_1rtt(
    quic_pcap_iter_t *  iter,
    uint                ip4_saddr,
    uchar const * const data,
    ulong               data_sz
) {
  (void)iter;
  (void)ip4_saddr;
  (void)data;
  (void)data_sz;
}

static void
quic_pcap_iter_deliver_datagram(
    quic_pcap_iter_t * iter,
    uint               ip4_saddr,
    uchar *            data,
    ulong              data_sz
) {

  //FD_LOG_HEXDUMP_NOTICE(( "datagram", data, data_sz ));
  while( data_sz ) {

    int is_long = fd_quic_h0_hdr_form( data[0] );
    if( is_long ) {

      int pkt_type = fd_quic_h0_long_packet_type( data[0] );
      ulong out_pkt_sz = data_sz;
      switch( pkt_type ) {
      case FD_QUIC_PKT_TYPE_INITIAL:
        quic_pcap_iter_deliver_initial( iter, ip4_saddr, data, data_sz, &out_pkt_sz );
        break;
      case FD_QUIC_PKT_TYPE_HANDSHAKE:
        quic_pcap_iter_deliver_handshake( iter, ip4_saddr, data, data_sz, &out_pkt_sz );
        break;
      }
      data    += out_pkt_sz;
      data_sz -= out_pkt_sz;

    } else {

      quic_pcap_iter_deliver_1rtt( iter, ip4_saddr, data, data_sz );
      data_sz = 0UL;
      break;

    }

  }

  (void)iter;
  (void)ip4_saddr;
}

static void
quic_pcap_iter_deliver_ethernet( quic_pcap_iter_t * iter,
                                 uchar *      const data,
                                 ulong        const data_sz ) {
  uchar * cur = data;
  uchar * end = data+data_sz;

  fd_eth_hdr_t const * eth_hdr = fd_type_pun_const( data );
  cur += sizeof(fd_eth_hdr_t);
  if( FD_UNLIKELY( cur>end ) ) return;
  if( FD_UNLIKELY( fd_ushort_bswap( eth_hdr->net_type )!=FD_ETH_HDR_TYPE_IP ) ) return;

  fd_ip4_hdr_t const * ip4_hdr = fd_type_pun_const( cur );
  if( FD_UNLIKELY( cur+sizeof(fd_ip4_hdr_t) > end ) ) return;
  cur += FD_IP4_GET_LEN( *ip4_hdr );
  if( FD_UNLIKELY( cur>end ) ) return;
  if( FD_UNLIKELY( ip4_hdr->protocol!=FD_IP4_HDR_PROTOCOL_UDP ) ) return;

  fd_udp_hdr_t const * udp_hdr = fd_type_pun_const( cur );
  if( FD_UNLIKELY( cur+sizeof(fd_udp_hdr_t) > end ) ) return;
  cur += sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( cur>end ) ) return;
  (void)udp_hdr;

  uint ip4_saddr = fd_uint_load_4( ip4_hdr->saddr_c );
  quic_pcap_iter_deliver_datagram( iter, ip4_saddr, cur, (ulong)( end-cur ) );
}

struct fd_sll_hdr {
  ushort packet_type;
  ushort arphrd_type;
  ushort ll_addr_sz;
  uchar  ll_addr[8];
  ushort protocol_type;
};

typedef struct fd_sll_hdr fd_sll_hdr_t;

static void
quic_pcap_iter_deliver_cooked( quic_pcap_iter_t *  iter,
                               uchar const * const data,
                               ulong         const data_sz ) {
  (void)iter; (void)data; (void)data_sz;
  FD_LOG_ERR(( "Linux SLL captures not yet supported" ));
}

static void
quic_pcap_iter_run_pcap( quic_pcap_iter_t * iter ) {

  fd_pcap_iter_t * pcap = fd_pcap_iter_new( iter->pcap_file );
  if( FD_UNLIKELY( !pcap ) ) FD_LOG_ERR(( "Failed to read pcap" ));

  ulong pcap_iter_type = fd_pcap_iter_type( pcap );
  int is_cooked;
  switch( pcap_iter_type ) {
  case FD_PCAP_ITER_TYPE_ETHERNET: is_cooked = 0; break;
  case FD_PCAP_ITER_TYPE_COOKED:   is_cooked = 1; break;
  default:
    FD_LOG_ERR(( "Unsupported pcap link type (%lu)", pcap_iter_type ));
  }

  for(;;) {
    uchar pkt[ 8192 ];
    long  ts;
    ulong sz = fd_pcap_iter_next( pcap, pkt, sizeof(pkt), &ts );
    if( FD_UNLIKELY( !sz ) ) break;
    if( is_cooked ) {
      quic_pcap_iter_deliver_ethernet( iter, pkt, sz );
    } else {
      quic_pcap_iter_deliver_cooked( iter, pkt, sz );
    }
  }

  (void)fd_pcap_iter_delete( pcap );

}

static void
quic_pcap_iter_run_pcapng( quic_pcap_iter_t * iter ) {

  void * pcap_iter_mem = aligned_alloc( fd_pcapng_iter_align(), fd_pcapng_iter_footprint() );
  fd_pcapng_iter_t * pcap = NULL;

  while( !feof( iter->pcap_file ) ) {

    if( !pcap ) {
      pcap = fd_pcapng_iter_new( pcap_iter_mem, iter->pcap_file );
      if( FD_UNLIKELY( !pcap ) ) FD_LOG_ERR(( "fd_pcapng_iter_new failed" ));
    }

    fd_pcapng_frame_t * frame = fd_pcapng_iter_next( pcap );
    if( FD_UNLIKELY( !frame ) ) {
      int err = fd_pcapng_iter_err( pcap );
      if( FD_LIKELY( err==-1 ) ) {
        (void)fd_pcapng_iter_delete( pcap );
        pcap = NULL;
        continue;
      }
      FD_LOG_ERR(( "Failed to read pcapng (%d-%s)", err, fd_io_strerror( err ) ));
    }

    if( frame->type==FD_PCAPNG_FRAME_TLSKEYS ) {
      quic_pcap_iter_add_keys( iter, (char const *)frame->data, frame->data_sz );
      continue;
    }
    if( frame->type!=FD_PCAPNG_FRAME_SIMPLE && frame->type!=FD_PCAPNG_FRAME_ENHANCED ) {
      continue;
    }

    uint link_type = pcap->iface[ frame->if_idx ].link_type;
    switch( link_type ) {
    case FD_PCAPNG_LINKTYPE_ETHERNET:
      quic_pcap_iter_deliver_ethernet( iter, (void *)frame->data, frame->data_sz );
      break;
    case FD_PCAPNG_LINKTYPE_COOKED:
      quic_pcap_iter_deliver_cooked( iter, frame->data, frame->data_sz );
      break;
    default:
      FD_LOG_NOTICE(( "Unsupported link type %#x", link_type ));
    }

  }

}

static void
quic_pcap_iter_run( quic_pcap_iter_t * iter ) {

  uint magic;
  if( FD_UNLIKELY( pread( fileno( iter->pcap_file ), &magic, sizeof(uint), 0 )!=sizeof(uint) ) ) {
    FD_LOG_ERR(( "Failed to detect pcap version (%d-%s)", errno, fd_io_strerror( errno ) ));
  }

  switch( magic ) {
  case 0xa1b2c3d4U:
  case 0xa1b23c4dU:
    quic_pcap_iter_run_pcap( iter );
    break;
  case 0x0a0d0d0aU:
    quic_pcap_iter_run_pcapng( iter );
    break;
  default:
    FD_LOG_ERR(( "Unsupported packet capture file format" ));
  }

}

int
main( int     argc,
      char ** argv ) {

  for( int i=1; i<argc; i++ ) {
    if( 0==strcmp( argv[i], "--help" ) ) {
      usage();
      return 0;
    }
  }

  setenv( "FD_LOG_PATH", "", 1 ); /* suppress logs for tools */
  fd_boot( &argc, &argv );

  //char const * key_file = fd_env_strip_cmdline_cstr ( &argc, &argv, "--key-file", NULL, NULL             );
  ulong        key_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--key-max",  NULL, MAX_KEYS_DEFAULT );
  reject_unknown_flags( &argc, &argv );

  argc--; argv++;
  if( FD_UNLIKELY( argc!=2 ) ) {
    usage_invalid();
    return 1;
  }

  char const * command   = argv[0];
  char const * pcap_path = argv[1];

  quic_pcap_params_t params = {
    .pcap_path = pcap_path,
    .key_max   = key_max
  };
  quic_pcap_iter_t iter_[1];
  quic_pcap_iter_t * iter = quic_pcap_iter_new( iter_, &params );
  if( FD_UNLIKELY( !iter ) ) {
    FD_LOG_ERR(( "Failed to initialize. Aborting" ));
  }

  (void)command;

  quic_pcap_iter_run( iter );

  /* Don't bother to close files on application exit */
  fd_halt();
  return 0;
}
