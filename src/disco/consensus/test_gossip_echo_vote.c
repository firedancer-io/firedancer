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
#include "../keyguard/fd_keyguard_client.h"
#include "../metrics/fd_metrics.h"
#include "../shred/fd_shred_cap.h"
#include "../tvu/fd_replay.h"
#include "../tvu/fd_store.h"

#include "../../choreo/fd_choreo.h"
#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/repair/fd_repair.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/fd_snapshot_loader.h"
#include "../../flamenco/runtime/program/fd_bpf_program_util.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../flamenco/types/fd_types.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

#define MAX_ADDR_STRLEN      128
#define TEST_CONSENSUS_MAGIC ( 0x7e57UL ) /* test */

uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 0, 0 ) ] __attribute__((aligned(FD_METRICS_ALIGN)));

static void
sign_fun( void * arg, uchar * sig, uchar const * buffer, ulong len ) {
  fd_gossip_config_t * config = (fd_gossip_config_t *)arg;
  fd_sha512_t          sha[1];
  fd_ed25519_sign( /* sig */ sig,
                   /* msg */ buffer,
                   /* sz  */ len,
                   /* public_key  */ config->public_key->uc,
                   /* private_key */ config->private_key,
                   sha );
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
    FD_LOG_ERR( ( "socket failed: %s", strerror( errno ) ) );
    return -1;
  }
  int optval = 1 << 20;
  if( setsockopt( fd, SOL_SOCKET, SO_RCVBUF, (char *)&optval, sizeof( int ) ) < 0 ) {
    FD_LOG_ERR( ( "setsocketopt failed: %s", strerror( errno ) ) );
    return -1;
  }

  if( setsockopt( fd, SOL_SOCKET, SO_SNDBUF, (char *)&optval, sizeof( int ) ) < 0 ) {
    FD_LOG_ERR( ( "setsocketopt failed: %s", strerror( errno ) ) );
    return -1;
  }

  uchar saddr[sizeof( struct sockaddr_in6 )];
  int   addrlen = to_sockaddr( saddr, addr );
  if( addrlen < 0 || bind( fd, (struct sockaddr *)saddr, (uint)addrlen ) < 0 ) {
    char tmp[MAX_ADDR_STRLEN];
    FD_LOG_ERR( ( "bind failed: %s for %s",
                  strerror( errno ),
                  fd_gossip_addr_str( tmp, sizeof( tmp ), addr ) ) );
    return -1;
  }
  if( getsockname( fd, (struct sockaddr *)saddr, (uint *)&addrlen ) < 0 ) {
    FD_LOG_ERR( ( "getsockname failed: %s", strerror( errno ) ) );
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
    FD_LOG_WARNING( ( "sendto failed: %s", strerror( errno ) ) );
  }
}

struct gossip_deliver_arg {
  fd_valloc_t        valloc;
  fd_gossip_t        *gossip;
  fd_gossip_config_t *gossip_config;

  const uchar* voter_keypair;
  const uchar* validator_keypair;
};
typedef struct gossip_deliver_arg gossip_deliver_arg_t;

/* functions for fd_gossip_config_t and fd_repair_config_t */
static void
gossip_deliver_fun( fd_crds_data_t * data, void * arg ) {
  gossip_deliver_arg_t * arg_ = (gossip_deliver_arg_t *)arg;
  if ( data->discriminant == fd_crds_data_enum_vote ) {
    fd_gossip_vote_t *vote = &data->inner.vote;
    fd_txn_t *parsed_txn = (fd_txn_t *)fd_type_pun( vote->txn.txn );

    FD_TEST( parsed_txn );
    FD_TEST( parsed_txn->instr_cnt == 1);

    uchar program_id = parsed_txn->instr[0].program_id;
    uchar* account_addr = (vote->txn.raw + parsed_txn->acct_addr_off
                           + FD_TXN_ACCT_ADDR_SZ * program_id );

    if ( !memcmp( account_addr, fd_solana_vote_program_id.key, sizeof( fd_pubkey_t ) ) ) {
      fd_vote_instruction_t vote_instr = { 0 };
      ushort instr_data_sz = parsed_txn->instr[0].data_sz;
      uchar* instr_data = vote->txn.raw + parsed_txn->instr[0].data_off;
      fd_bincode_decode_ctx_t decode = {
                                        .data    = instr_data,
                                        .dataend = instr_data + instr_data_sz,
                                        .valloc  = arg_->valloc
      };
      int decode_result = fd_vote_instruction_decode( &vote_instr, &decode );
      if( decode_result == FD_BINCODE_SUCCESS) {
        if  ( vote_instr.discriminant == fd_vote_instruction_enum_compact_update_vote_state ) {
          /* Replace the timestamp in compact_update_vote_state */
          static ulong MAGIC_TIMESTAMP = 19950128;
          vote_instr.inner.compact_update_vote_state.timestamp = &MAGIC_TIMESTAMP;
          fd_bincode_encode_ctx_t encode = { .data = instr_data, .dataend = instr_data + instr_data_sz };
          fd_vote_instruction_encode ( &vote_instr, &encode );
          FD_TEST( fd_vote_instruction_size( &vote_instr) == instr_data_sz );

          #define SIGNATURE_SZ 64
          uchar validator_sig[ SIGNATURE_SZ ], voter_sig[ SIGNATURE_SZ ];
          fd_sha512_t sha[2];
          fd_ed25519_sign( /* sig */ validator_sig,
                           /* msg */ vote->txn.raw + parsed_txn->message_off,
                           /* sz  */ vote->txn.raw_sz - parsed_txn->message_off,
                           /* public_key  */ arg_->validator_keypair + 32UL,//  arg_->gossip_config->public_key->uc,
                           /* private_key */ arg_->validator_keypair,//arg_->gossip_config->private_key,
                           &sha[0] );
          fd_ed25519_sign( /* sig */ voter_sig,
                           /* msg */ vote->txn.raw + parsed_txn->message_off,
                           /* sz  */ vote->txn.raw_sz - parsed_txn->message_off,
                           /* public_key  */ arg_->voter_keypair + 32UL,//  arg_->gossip_config->public_key->uc,
                           /* private_key */ arg_->voter_keypair,//arg_->gossip_config->private_key,
                           &sha[0] );
          uchar* sign_addr = vote->txn.raw + parsed_txn->signature_off;
          FD_LOG_WARNING(("Old signatures: %32J, %32J || New signatures: %32J, %32J", sign_addr, sign_addr + SIGNATURE_SZ, validator_sig, voter_sig));
          memcpy(sign_addr, validator_sig, SIGNATURE_SZ);
          memcpy(sign_addr + SIGNATURE_SZ, voter_sig, SIGNATURE_SZ);
          fd_gossip_push_value( arg_->gossip, data, NULL );
          FD_LOG_NOTICE( ("Echo gossip vote: from=%32J, gossip_pubkey=%32J, txn_acct_cnt=%u(readonly_s=%u, readonly_us=%u), sign_cnt=%u, sign_off=%u | instruction#0: program=%32J",
                          &vote->from,
                          arg_->gossip_config->public_key,
                          parsed_txn->acct_addr_cnt,
                          parsed_txn->readonly_signed_cnt,
                          parsed_txn->readonly_unsigned_cnt,
                          parsed_txn->signature_cnt,
                          parsed_txn->signature_off,
                          account_addr) );

       } else {
          FD_LOG_WARNING( ("Gossip receives vote instruction with other discriminant") );
        }
      } else {
        FD_LOG_ERR( ("Unable to decode the vote instruction in gossip, error=%d", decode_result) );
      }
    } else {
      FD_LOG_ERR( ("Received gossip vote txn targets program %32J instead of %32J",
                   account_addr,
                   fd_solana_vote_program_id.key) );
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
      FD_LOG_ERR( ( "missing colon" ) );
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
    FD_LOG_WARNING( ( "unable to resolve host %s", buf ) );
    return NULL;
  }
  /* Convert result to repair address */
  res->l    = 0;
  res->addr = ( (struct in_addr *)host->h_addr_list[0] )->s_addr;
  int port  = atoi( str + i + 1 );
  if( ( port > 0 && port < 1024 ) || port > (int)USHORT_MAX ) {
    FD_LOG_ERR( ( "invalid port number" ) );
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

//static int
//gossip_thread( FD_PARAM_UNUSED int argc, char ** argv ) {
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
      FD_LOG_ERR( ( "recvmmsg failed: %s", strerror( errno ) ) );
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
  FD_TEST( gossip_peer_addr );
  const char * voter_keypair_file =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--voter-keypair-file", NULL, NULL );
   const char * validator_keypair_file =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--validator-keypair-file", NULL, NULL );
  FD_TEST( voter_keypair_file );
  FD_TEST( validator_keypair_file );

  /**********************************************************************/
  /* wksp                                                               */
  /**********************************************************************/

  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                   1,
                   _page_sz,
                   numa_idx ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      fd_cstr_to_shmem_page_sz( _page_sz ), 1, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );
  FD_LOG_DEBUG( ( "Finish setup wksp" ) );

  /**********************************************************************/
  /* alloc                                                              */
  /**********************************************************************/

  void * alloc_shmem =
      fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), TEST_CONSENSUS_MAGIC );
  void *       alloc_shalloc = fd_alloc_new( alloc_shmem, TEST_CONSENSUS_MAGIC );
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
      fd_wksp_alloc_laddr( wksp, fd_gossip_align(), fd_gossip_footprint(), TEST_CONSENSUS_MAGIC );
  fd_gossip_t * gossip =
      fd_gossip_join( fd_gossip_new( gossip_shmem, TEST_CONSENSUS_MAGIC ) );

  fd_gossip_config_t gossip_config;
  gossip_config.public_key  = &public_key;
  gossip_config.private_key = private_key;
  char gossip_addr[7]       = { 0 };
  snprintf( gossip_addr, sizeof( gossip_addr ), ":%u", gossip_port );
  FD_TEST( resolve_hostport( gossip_addr, &gossip_config.my_addr ) );
  gossip_config.shred_version             = 0;
  gossip_config.deliver_fun               = gossip_deliver_fun;
  gossip_deliver_arg_t gossip_deliver_arg = { .valloc = valloc,
                                              .gossip_config = &gossip_config,
                                              .gossip = gossip,
                                              .voter_keypair = fd_keyload_load(voter_keypair_file, 0),
                                              .validator_keypair = fd_keyload_load(validator_keypair_file, 0)};
  gossip_config.deliver_arg               = &gossip_deliver_arg;
  gossip_config.send_fun                  = gossip_send_fun;
  int gossip_sockfd                       = create_socket( &gossip_config.my_addr );
  gossip_config.send_arg                  = &gossip_sockfd;
  gossip_config.sign_fun                  = sign_fun;
  gossip_config.sign_arg                  = &gossip_config;

  FD_TEST( !fd_gossip_set_config( gossip, &gossip_config ) );

  fd_gossip_peer_addr_t _gossip_peer_addr;
  FD_TEST( !fd_gossip_add_active_peer( gossip,
                                       resolve_hostport( gossip_peer_addr, &_gossip_peer_addr ) ) );

  fd_gossip_update_addr( gossip, &gossip_config.my_addr );
  fd_gossip_settime( gossip, fd_log_wallclock() );
  fd_gossip_start( gossip );

  /**********************************************************************/
  /* gossip thread                                                      */
  /**********************************************************************/

  gossip_targ_t gossip_targ = { .gossip_fd = gossip_sockfd, .valloc = valloc, .gossip = gossip };
  //FD_TEST( fd_tile_exec_new( 1, gossip_thread, 0, fd_type_pun( &gossip_targ ) ) );
  pthread_t t;
  pthread_create(&t, NULL, gossip_thread, &gossip_targ);
  while( FD_LIKELY( 1 /* !fd_tile_shutdown_flag */ ) );

  fd_halt();
  return 0;
}
