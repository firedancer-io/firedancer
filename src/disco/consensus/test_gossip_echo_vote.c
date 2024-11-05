#define _GNU_SOURCE /* See feature_test_macros(7) */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../keyguard/fd_keyload.h"
#include "../keyguard/fd_keyguard.h"
#include "../keyguard/fd_keyguard_client.h"
#include "../metrics/fd_metrics.h"
#include "../shred/fd_shred_cap.h"
#include "../store/fd_store.h"

#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_udp.h"
#include "../../waltz/aio/fd_aio.h"
#include "../../waltz/udpsock/fd_udpsock.h"

#include "../../choreo/fd_choreo.h"
#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/repair/fd_repair.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/program/fd_bpf_program_util.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../flamenco/types/fd_types.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"

#define MAX_ADDR_STRLEN        128
#define TEST_GOSSIP_VOTE_MAGIC ( 0x7e57UL ) /* test */

uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 0, 0 ) ] __attribute__((aligned(FD_METRICS_ALIGN)));

static void
sign_fun( void * arg, uchar * sig, uchar const * buffer, ulong len, int sign_type ) {
  fd_gossip_config_t * config = (fd_gossip_config_t *)arg;
  fd_sha512_t          sha[1];

  switch( sign_type ) {

  case FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519: {
    uchar hash[32];
    fd_sha256_hash( buffer, len, hash );
    fd_ed25519_sign( /* sig */ sig,
                     /* msg */ hash,
                     /* sz  */ 32,
                     /* public_key  */ config->public_key->uc,
                     /* private_key */ config->private_key,
                     sha );
    break;
  }

  case FD_KEYGUARD_SIGN_TYPE_ED25519:
    fd_ed25519_sign( /* sig */ sig,
                     /* msg */ buffer,
                     /* sz  */ len,
                     /* public_key  */ config->public_key->uc,
                     /* private_key */ config->private_key,
                     sha );
    break;

  default:
    FD_LOG_CRIT(( "Invalid sign type %d", sign_type ));
  }
}

static int
to_sockaddr( uchar * dst, fd_gossip_peer_addr_t const * src ) {
  fd_memset( dst, 0, sizeof( struct sockaddr_in ) );
  struct sockaddr_in * t = (struct sockaddr_in *)dst;
  t->sin_family          = AF_INET;
  t->sin_addr.s_addr     = src->addr;
  t->sin_port            = src->port;
  return sizeof( struct sockaddr_in );
}

/* Convert my style of address from UNIX style */
static int
from_sockaddr( fd_gossip_peer_addr_t * dst, uchar const * src ) {
  FD_STATIC_ASSERT( sizeof( fd_gossip_peer_addr_t ) == sizeof( ulong ), "messed up size" );
  dst->l                        = 0;
  const struct sockaddr_in * sa = (const struct sockaddr_in *)src;
  dst->addr                     = sa->sin_addr.s_addr;
  dst->port                     = sa->sin_port;
  return 0;
}

static int
create_socket( fd_gossip_peer_addr_t * addr ) {
  int fd;
  if( ( fd = socket( AF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {
    FD_LOG_ERR(( "socket failed: %s", strerror( errno ) ));
    return -1;
  }
  int optval = 1 << 20;
  if( setsockopt( fd, SOL_SOCKET, SO_RCVBUF, (char *)&optval, sizeof( int ) ) < 0 ) {
    FD_LOG_ERR(( "setsocketopt failed: %s", strerror( errno ) ));
    return -1;
  }

  if( setsockopt( fd, SOL_SOCKET, SO_SNDBUF, (char *)&optval, sizeof( int ) ) < 0 ) {
    FD_LOG_ERR(( "setsocketopt failed: %s", strerror( errno ) ));
    return -1;
  }

  uchar saddr[sizeof( struct sockaddr_in6 )];
  int   addrlen = to_sockaddr( saddr, addr );
  if( addrlen < 0 || bind( fd, (struct sockaddr *)saddr, (uint)addrlen ) < 0 ) {
    char tmp[MAX_ADDR_STRLEN];
    FD_LOG_ERR(( "bind failed: %s for %s",
                 strerror( errno ),
                 fd_gossip_addr_str( tmp, sizeof( tmp ), addr ) ));
    return -1;
  }
  if( getsockname( fd, (struct sockaddr *)saddr, (uint *)&addrlen ) < 0 ) {
    FD_LOG_ERR(( "getsockname failed: %s", strerror( errno ) ));
    return -1;
  }
  from_sockaddr( addr, saddr );

  return fd;
}

static void
gossip_send_fun( uchar const *                 data,
                 size_t                        sz,
                 fd_gossip_peer_addr_t const * gossip_peer_addr,
                 void *                        arg ) {
  uchar saddr[sizeof( struct sockaddr_in )];
  int   saddrlen           = to_sockaddr( saddr, gossip_peer_addr );
  char  s[MAX_ADDR_STRLEN] = { 0 };
  fd_gossip_addr_str( s, sizeof( s ), gossip_peer_addr );
  if( sendto( *(int *)arg,
              data,
              sz,
              MSG_DONTWAIT,
              (const struct sockaddr *)saddr,
              (socklen_t)saddrlen ) < 0 ) {
    FD_LOG_WARNING(( "sendto failed: %s", strerror( errno ) ));
  }
}

void send_udp_pkt( void * pkt, ulong pkt_sz, fd_wksp_t * wksp, uint dst_ip, ushort dst_port ) {
  ulong        mtu          = 2048UL;
  ulong        rx_depth     = 1024UL;
  ulong        tx_depth     = 1024UL;

  int sock_fd = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
  if( FD_UNLIKELY( sock_fd<0 ) ) {
    FD_LOG_ERR(( "socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP) failed" ));
  }

  void * sock_mem = fd_wksp_alloc_laddr( wksp, fd_udpsock_align(),
                                         fd_udpsock_footprint( mtu, rx_depth, tx_depth ),
                                         1UL );
  if( FD_UNLIKELY( !sock_mem ) ) {
    FD_LOG_WARNING(( "fd_wksp_alloc_laddr() failed" ));
    close( sock_fd );
    return;
  }

  fd_udpsock_t * sock = fd_udpsock_join( fd_udpsock_new( sock_mem, mtu, rx_depth, tx_depth ), sock_fd );
  if( FD_UNLIKELY( !sock ) ) {
    FD_LOG_WARNING(( "fd_udpsock_join() failed" ));
    close( sock_fd );
    fd_wksp_free_laddr( sock_mem );
    return;
  }

  fd_aio_pkt_info_t pkt_info[1];
  uchar buf[2048];
  uchar * write_ptr = buf;

  fd_eth_hdr_t eth_hdr = {.net_type = htons( 0x0800 )};
  fd_ip4_hdr_t ip_hdr;
  fd_memset( &ip_hdr, 0, sizeof(fd_ip4_hdr_t) );
  ip_hdr.verihl = sizeof(fd_ip4_hdr_t) / 4;
  fd_memcpy( ip_hdr.daddr_c, &dst_ip, 4) ;
  fd_ip4_hdr_bswap( &ip_hdr );
  fd_udp_hdr_t udp_hdr;
  fd_memset( &udp_hdr, 0, sizeof(fd_udp_hdr_t) );
  udp_hdr.net_dport = dst_port;
  fd_udp_hdr_bswap( &udp_hdr );

  fd_memcpy( write_ptr, &eth_hdr, sizeof(fd_eth_hdr_t) );
  write_ptr += sizeof( fd_eth_hdr_t );
  fd_memcpy( write_ptr, &ip_hdr, FD_IP4_GET_LEN(ip_hdr) );
  write_ptr += sizeof( fd_ip4_hdr_t );
  fd_memcpy( write_ptr, &udp_hdr, sizeof( fd_udp_hdr_t) );
  write_ptr += sizeof( fd_udp_hdr_t );
  fd_memcpy( write_ptr, pkt, pkt_sz );
  pkt_info->buf = buf;

  ulong buf_sz = pkt_sz + (ulong)(write_ptr - buf);
  if ( buf_sz <= USHORT_MAX ) {
    pkt_info->buf_sz = (ushort) buf_sz;
  } else {
    FD_LOG_ERR(( "Packet size overflows ushort" ));
  }

  fd_aio_t const * tx = fd_udpsock_get_tx( sock );
  int rc = tx->send_func(tx->ctx, pkt_info, 1, NULL, 1);
  if ( rc != FD_AIO_SUCCESS ) {
    FD_LOG_ERR(( "UDP send failed with %d", rc ));
  } else {
    uchar * data = (uchar *)pkt;
    FD_LOG_NOTICE(( "UDP send suceeds\n %lu bytes in total. first 8 bytes: %x %x %x %x %x %x %x %x | last  8 bytes: %x %x %x %x %x %x %x %x\n ", pkt_sz, data[0], data[1], data[2], data[3],
                    data[4], data[5], data[6], data[7], data[pkt_sz - 8], data[pkt_sz - 7], data[pkt_sz - 6], data[pkt_sz -5],
                    data[pkt_sz - 4], data[pkt_sz - 3], data[pkt_sz - 2], data[pkt_sz - 1] ));
  }
}

struct gossip_deliver_arg {
  fd_wksp_t *          wksp;
  fd_valloc_t          valloc;
  fd_gossip_t        * gossip;
  fd_gossip_config_t * gossip_config;

  fd_pubkey_t const  * vote_acct_addr;
  const uchar        * vote_authority_keypair;
  const uchar        * validator_identity_keypair;
};
typedef struct gossip_deliver_arg gossip_deliver_arg_t;

struct vote_txn_sign_args {
  const uchar * vote_authority_keypair;
  const uchar * validator_identity_keypair;
};
typedef struct vote_txn_sign_args vote_txn_sign_args_t;

void
vote_txn_validator_identity_signer( void *        _keys,
                                    uchar         signature[ static 64 ],
                                    uchar const * buffer,
                                    ulong         len ) {
    fd_sha512_t sha;
    vote_txn_sign_args_t * keys = (vote_txn_sign_args_t *) fd_type_pun( _keys );
    fd_ed25519_sign( /* sig */ signature,
                     /* msg */ buffer,
                     /* sz  */ len,
                     /* public_key  */ keys->validator_identity_keypair + 32UL,
                     /* private_key */ keys->validator_identity_keypair,
                     &sha );
}

void
vote_txn_vote_authority_signer( void *        _keys,
                                uchar         signature[ static 64 ],
                                uchar const * buffer,
                                ulong         len ) {
    fd_sha512_t sha;
    vote_txn_sign_args_t * keys = (vote_txn_sign_args_t *) fd_type_pun( _keys );
    fd_ed25519_sign( /* sig */ signature,
                     /* msg */ buffer,
                     /* sz  */ len,
                     /* public_key  */ keys->vote_authority_keypair + 32UL,
                     /* private_key */ keys->vote_authority_keypair,
                     &sha );
}

static void
gossip_deliver_fun( fd_crds_data_t * data, void * arg ) {
  gossip_deliver_arg_t * arg_ = (gossip_deliver_arg_t *)arg;
  if( data->discriminant == fd_crds_data_enum_vote ) {
    fd_gossip_vote_t * vote = &data->inner.vote;
    fd_txn_t * parsed_txn = (fd_txn_t *)fd_type_pun( vote->txn.txn );

    FD_TEST( parsed_txn );
    FD_TEST( parsed_txn->instr_cnt == 1);

    uchar program_id = parsed_txn->instr[0].program_id;
    uchar* account_addr = (vote->txn.raw + parsed_txn->acct_addr_off
                           + FD_TXN_ACCT_ADDR_SZ * program_id );

    if ( !memcmp( account_addr, fd_solana_vote_program_id.key, sizeof( fd_pubkey_t ) ) ) {
      fd_vote_instruction_t vote_instr = { 0 };
      ushort instr_data_sz             = parsed_txn->instr[0].data_sz;
      uchar * instr_data               = vote->txn.raw + parsed_txn->instr[0].data_off;
      fd_bincode_decode_ctx_t decode   = {
        .data    = instr_data,
        .dataend = instr_data + instr_data_sz,
        .valloc  = arg_->valloc
      };
      int decode_result = fd_vote_instruction_decode( &vote_instr, &decode );
      if( decode_result == FD_BINCODE_SUCCESS) {
        if( vote_instr.discriminant == fd_vote_instruction_enum_compact_update_vote_state ) {
          /* Replace the timestamp in compact_update_vote_state */
          /* FIXME What is this random timestamp? */
          long new_timestamp = 19950128L;
          vote_instr.inner.compact_update_vote_state.has_timestamp = 1;
          vote_instr.inner.compact_update_vote_state.timestamp = new_timestamp;

          /* Generate the vote transaction */
          FD_PARAM_UNUSED vote_txn_sign_args_t sign_args = {
            .vote_authority_keypair     = arg_->vote_authority_keypair,
            .validator_identity_keypair = arg_->validator_identity_keypair
          };
          fd_pubkey_t const * vote_authority_pubkey     = (fd_pubkey_t const *)fd_type_pun_const( arg_->vote_authority_keypair + 32UL );
          fd_pubkey_t const * validator_identity_pubkey = (fd_pubkey_t const *)fd_type_pun_const( arg_->validator_identity_keypair + 32UL );
          fd_voter_t voter = {
            .vote_acc_addr              = *arg_->vote_acct_addr,
            .vote_authority       = *vote_authority_pubkey,
            .validator_identity   = *validator_identity_pubkey
          };
          fd_crds_data_t echo_data;
          echo_data.discriminant          = fd_crds_data_enum_vote;
          echo_data.inner.vote.txn.raw_sz = fd_voter_txn_generate( &voter,
                                                                  &vote_instr.inner.compact_update_vote_state,
                                                                  (fd_hash_t *)fd_type_pun(vote->txn.raw + parsed_txn->recent_blockhash_off),
                                                                  echo_data.inner.vote.txn.txn_buf,
                                                                  echo_data.inner.vote.txn.raw );
          /* echo through gossip  */
          fd_gossip_push_value( arg_->gossip, &echo_data, NULL );
          static ulong echo_cnt = 0;
          FD_LOG_NOTICE(( "Echo gossip vote#%lu: root=%lu, from=%s, gossip_pubkey=%s, txn_acct_cnt=%u(readonly_s=%u, readonly_us=%u), sign_cnt=%u, sign_off=%u | instruction#0: program=%s",
                          echo_cnt++,
                          vote_instr.inner.compact_update_vote_state.root,
                          FD_BASE58_ENC_32_ALLOCA( &vote->from ),
                          FD_BASE58_ENC_32_ALLOCA( arg_->gossip_config->public_key ),
                          parsed_txn->acct_addr_cnt,
                          parsed_txn->readonly_signed_cnt,
                          parsed_txn->readonly_unsigned_cnt,
                          parsed_txn->signature_cnt,
                          parsed_txn->signature_off,
                          FD_BASE58_ENC_32_ALLOCA( account_addr ) ));

          /* echo through udp  */
          fd_aio_pkt_info_t udp_pkt;
          udp_pkt.buf     = echo_data.inner.vote.txn.raw;
          udp_pkt.buf_sz  = (ushort)echo_data.inner.vote.txn.raw_sz;
          uint   dst_ip   = 0x0100007f; /* localhost */
          ushort dst_port = 1029;       /* vote udp port */
          send_udp_pkt( udp_pkt.buf, udp_pkt.buf_sz, arg_->wksp, dst_ip, dst_port );
          FD_LOG_NOTICE(( "Sent vote txn to 127.0.0.1:1029 w/ UDP\ntimestamp: %ld\nOld sig1: %s\nOld sig2: %s\nNew sig1: %s\nNew sig2: %s",
                         new_timestamp,
                         FD_BASE58_ENC_64_ALLOCA( vote->txn.raw + parsed_txn->signature_off ),
                         FD_BASE58_ENC_64_ALLOCA( vote->txn.raw + parsed_txn->signature_off + FD_TXN_SIGNATURE_SZ ),
                         FD_BASE58_ENC_64_ALLOCA( echo_data.inner.vote.txn.raw + parsed_txn->signature_off ),
                         FD_BASE58_ENC_64_ALLOCA( echo_data.inner.vote.txn.raw + parsed_txn->signature_off + FD_TXN_SIGNATURE_SZ ) ));
          FD_LOG_ERR(( "Finish." ));

       } else {
          FD_LOG_WARNING(( "Gossip receives vote instruction with other discriminant" ));
        }
      } else {
        FD_LOG_ERR(( "Unable to decode the vote instruction in gossip, error=%d", decode_result ));
      }
    } else {
      FD_LOG_ERR(( "Received gossip vote txn targets program %s instead of %s",
                   FD_BASE58_ENC_32_ALLOCA( account_addr ),
                   FD_BASE58_ENC_32_ALLOCA( fd_solana_vote_program_id.key ) ));
    }
  }
}

/* Convert a host:port string to a repair network address. If host is
 * missing, it assumes the local hostname. */
static fd_repair_peer_addr_t *
resolve_hostport( const char * str /* host:port */, fd_repair_peer_addr_t * res ) {
  fd_memset( res, 0, sizeof( fd_repair_peer_addr_t ) );

  /* Find the : and copy out the host */
  char buf[MAX_ADDR_STRLEN];
  uint i;
  for( i = 0;; ++i ) {
    if( str[i] == '\0' || i > sizeof( buf ) - 1U ) {
      FD_LOG_ERR(( "missing colon" ));
      return NULL;
    }
    if( str[i] == ':' ) {
      buf[i] = '\0';
      break;
    }
    buf[i] = str[i];
  }
  if( i == 0 || strcmp( buf, "localhost" ) == 0 ||
      strcmp( buf, "127.0.0.1" ) == 0 ) /* :port means $HOST:port */
    gethostname( buf, sizeof( buf ) );

  struct hostent * host = gethostbyname( buf );
  if( host == NULL ) {
    FD_LOG_WARNING(( "unable to resolve host %s", buf ));
    return NULL;
  }
  /* Convert result to repair address */
  res->l    = 0;
  res->addr = ( (struct in_addr *)host->h_addr_list[0] )->s_addr;
  int port  = atoi( str + i + 1 );
  if( ( port > 0 && port < 1024 ) || port > (int)USHORT_MAX ) {
    FD_LOG_ERR(( "invalid port number" ));
    return NULL;
  }
  res->port = htons( (ushort)port );

  return res;
}

struct gossip_targ {
  int           gossip_fd;
  fd_valloc_t   valloc;
  fd_gossip_t * gossip;
};
typedef struct gossip_targ gossip_targ_t;

#define VLEN 32U
#define CLEAR_MSGS                                                                                 \
  fd_memset( msgs, 0, sizeof( msgs ) );                                                            \
  for( uint i = 0; i < VLEN; i++ ) {                                                               \
    iovecs[i].iov_base          = bufs[i];                                                         \
    iovecs[i].iov_len           = FD_ETH_PAYLOAD_MAX;                                              \
    msgs[i].msg_hdr.msg_iov     = &iovecs[i];                                                      \
    msgs[i].msg_hdr.msg_iovlen  = 1;                                                               \
    msgs[i].msg_hdr.msg_name    = sockaddrs[i];                                                    \
    msgs[i].msg_hdr.msg_namelen = sizeof( struct sockaddr_in6 );                                   \
  }

void*
gossip_thread( void* arg ) {
  gossip_targ_t * _arg      = (gossip_targ_t *)arg;
  int             gossip_fd = _arg->gossip_fd;
  fd_gossip_t *   gossip    = _arg->gossip;

  ulong  smax   = 1UL << 21UL;
  ulong  sdepth = 1UL << 5UL;
  void * smem =
    fd_valloc_malloc( _arg->valloc, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax ) );
  void * fmem =
    fd_valloc_malloc( _arg->valloc, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( sdepth ) );
  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, smax, sdepth );

  struct mmsghdr msgs[VLEN];
  struct iovec   iovecs[VLEN];
  uchar          bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar sockaddrs[VLEN][sizeof( struct sockaddr_in6 )]; /* sockaddr is smaller than sockaddr_in6 */
  while( FD_LIKELY( 1 /* !fd_tile_shutdown_flag */ ) ) {
    long now = fd_log_wallclock();
    fd_gossip_settime( gossip, now );

    /* Loop gossip */
    fd_gossip_continue( gossip );

    /* Read more packets */
    CLEAR_MSGS;
    int gossip_rc = recvmmsg( gossip_fd, msgs, VLEN, MSG_DONTWAIT, NULL );
    if( gossip_rc < 0 ) {
      if( errno == EINTR || errno == EWOULDBLOCK ) continue;
      break;
    }

    for( uint i = 0; i < (uint)gossip_rc; ++i ) {
      fd_gossip_peer_addr_t from;
      from_sockaddr( &from, msgs[i].msg_hdr.msg_name );
      fd_gossip_recv_packet( gossip, bufs[i], msgs[i].msg_len, &from );
    }
  }
  return 0;
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL, 0UL ) );

  const char * gossip_peer_addr =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--gossip-peer-addr", NULL, NULL );
  ushort gossip_port = fd_env_strip_cmdline_ushort( &argc, &argv, "--gossip-port", NULL, 9001 );
  const char * vote_acct_addr_file =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--vote-acct-addr-file", NULL, NULL );
  const char * vote_authority_keypair_file =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--vote-auth-keypair-file", NULL, NULL );
  const char * validator_identity_keypair_file =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--validator-id-keypair-file", NULL, NULL );
  ushort shred_version = fd_env_strip_cmdline_ushort( &argc, &argv, "--shred-version", NULL, 0 );

  FD_TEST( gossip_peer_addr );
  FD_TEST( vote_authority_keypair_file );
  FD_TEST( validator_identity_keypair_file );

  /**********************************************************************/
  /* wksp                                                               */
  /**********************************************************************/

  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                   1UL,
                   _page_sz,
                   numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      fd_cstr_to_shmem_page_sz( _page_sz ), 1, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );
  FD_LOG_DEBUG(( "Finish setup wksp" ));

  /**********************************************************************/
  /* alloc                                                              */
  /**********************************************************************/

  void * alloc_shmem =
      fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), TEST_GOSSIP_VOTE_MAGIC );
  void *       alloc_shalloc = fd_alloc_new( alloc_shmem, TEST_GOSSIP_VOTE_MAGIC );
  fd_alloc_t * alloc         = fd_alloc_join( alloc_shalloc, 0UL );
  fd_valloc_t  valloc        = fd_alloc_virtual( alloc );

  /**********************************************************************/
  /* scratch                                                            */
  /**********************************************************************/

  ulong  smax   = 1UL << 21UL;
  ulong  sdepth = 1UL << 5UL;
  void * smem =
      fd_valloc_malloc( valloc, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax ) );
  void * fmem =
      fd_valloc_malloc( valloc, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( sdepth ) );
  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, smax, sdepth );

  /**********************************************************************/
  /* keys                                                               */
  /**********************************************************************/

  uchar private_key[32];
  FD_TEST( 32UL == getrandom( private_key, 32UL, 0 ) );
  fd_sha512_t sha[1];
  fd_pubkey_t public_key;
  FD_TEST( fd_ed25519_public_from_private( public_key.uc, private_key, sha ) );

  /**********************************************************************/
  /* gossip                                                             */
  /**********************************************************************/

  void * gossip_shmem =
      fd_wksp_alloc_laddr( wksp, fd_gossip_align(), fd_gossip_footprint(), TEST_GOSSIP_VOTE_MAGIC );
  fd_gossip_t * gossip =
      fd_gossip_join( fd_gossip_new( gossip_shmem, TEST_GOSSIP_VOTE_MAGIC ) );

  fd_gossip_config_t gossip_config;
  char gossip_addr[7] = { 0 };
  snprintf( gossip_addr, sizeof( gossip_addr ), ":%u", gossip_port );
  FD_TEST( resolve_hostport( gossip_addr, &gossip_config.my_addr ) );
  gossip_config.shred_version             = shred_version;
  gossip_deliver_arg_t gossip_deliver_arg = {
    .valloc                     = valloc,
    .gossip_config              = &gossip_config,
    .gossip                     = gossip,
    .wksp                       = wksp,
    .vote_acct_addr             = (fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( vote_acct_addr_file, 1 ) ),
    .vote_authority_keypair     = fd_keyload_load( vote_authority_keypair_file, 0 ),
    .validator_identity_keypair = fd_keyload_load( validator_identity_keypair_file, 0 )
  };
  gossip_config.deliver_arg               = &gossip_deliver_arg;
  gossip_config.deliver_fun               = gossip_deliver_fun;
  gossip_config.send_fun                  = gossip_send_fun;
  int gossip_sockfd                       = create_socket( &gossip_config.my_addr );
  gossip_config.send_arg                  = &gossip_sockfd;
  gossip_config.public_key                = &public_key;
  gossip_config.private_key               = private_key;
  gossip_config.sign_fun                  = sign_fun;
  gossip_config.sign_arg                  = &gossip_config;
  gossip_config.my_version                = (fd_gossip_version_v2_t){
    .from = public_key,
    .major = 1337U,
    .minor = 1337U,
    .patch = 1337U,
    .commit = 0U,
    .has_commit = 0U,
    .feature_set = 0U,
  };
  FD_TEST( !fd_gossip_set_config( gossip, &gossip_config ) );

  uint entrypoints[16];
  fd_gossip_peer_addr_t _gossip_peer_addr;
  resolve_hostport( gossip_peer_addr, &_gossip_peer_addr );
  entrypoints[0] = _gossip_peer_addr.addr;
  ushort port = fd_ushort_bswap(_gossip_peer_addr.port);
  fd_gossip_set_entrypoints( gossip, entrypoints, 1, &port);

  fd_gossip_update_addr( gossip, &gossip_config.my_addr );
  fd_gossip_settime( gossip, fd_log_wallclock() );
  fd_gossip_start( gossip );

  /**********************************************************************/
  /* gossip thread                                                      */
  /**********************************************************************/

  gossip_targ_t gossip_targ = { .gossip_fd = gossip_sockfd, .valloc = valloc, .gossip = gossip };
  pthread_t t;
  pthread_create(&t, NULL, gossip_thread, &gossip_targ);
  while( FD_LIKELY( 1 /* !fd_tile_shutdown_flag */ ) ) {
    /* Allow other threads to add pendings */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)1e6 };
    nanosleep( &ts, NULL );
  }

  fd_halt();
  return 0;
}
