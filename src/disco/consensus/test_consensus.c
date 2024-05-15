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

#include "../keyguard/fd_keyguard_client.h"
#include "../metrics/fd_metrics.h"
#include "../shred/fd_shred_cap.h"
#include "../tvu/fd_replay.h"
#include "../tvu/fd_store.h"

#include "../../choreo/fd_choreo.h"
#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/repair/fd_repair.h"
#include "../../flamenco/runtime/fd_hashes.h"
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

uchar metrics_scratch[FD_METRICS_FOOTPRINT( 0, 0 )]
    __attribute__( ( aligned( FD_METRICS_ALIGN ) ) );

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

struct gossip_deliver_arg {
  fd_bft_t *    bft;
  fd_repair_t * repair;
  fd_valloc_t   valloc;
};
typedef struct gossip_deliver_arg gossip_deliver_arg_t;

/* functions for fd_gossip_config_t and fd_repair_config_t */
static void
gossip_deliver_fun( fd_crds_data_t * data, void * arg ) {
  gossip_deliver_arg_t * arg_ = (gossip_deliver_arg_t *)arg;
  if( data->discriminant == fd_crds_data_enum_contact_info_v1 ) {
    fd_repair_peer_addr_t repair_peer_addr = { 0 };
    fd_gossip_from_soladdr( &repair_peer_addr, &data->inner.contact_info_v1.serve_repair );
    if( repair_peer_addr.port == 0 ) return;
    if( FD_UNLIKELY( fd_repair_add_active_peer(
            arg_->repair, &repair_peer_addr, &data->inner.contact_info_v1.id ) ) ) {
      FD_LOG_DEBUG( ( "error adding peer" ) ); /* Probably filled up the table */
    };
  }
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

struct repair_arg {
  fd_replay_t * replay;
  int           sockfd;
};
typedef struct repair_arg repair_arg_t;

static void
repair_deliver_fun( fd_shred_t const *                            shred,
                    FD_PARAM_UNUSED ulong                         shred_sz,
                    FD_PARAM_UNUSED fd_repair_peer_addr_t const * from,
                    FD_PARAM_UNUSED fd_pubkey_t const *           id,
                    void *                                        arg ) {
  repair_arg_t * _arg = (repair_arg_t *)arg;
  fd_replay_repair_rx( _arg->replay, shred );
}

static void
repair_deliver_fail_fun( fd_pubkey_t const * id,
                         ulong               slot,
                         uint                shred_index,
                         void *              arg,
                         int                 reason ) {
  (void)arg;
  FD_LOG_WARNING( ( "repair_deliver_fail_fun - shred: %32J, slot: %lu, idx: %u, reason: %d",
                    id,
                    slot,
                    shred_index,
                    reason ) );
}

static void
repair_send_fun( uchar const * data, size_t sz, fd_repair_peer_addr_t const * addr, void * arg ) {
  repair_arg_t * _arg = (repair_arg_t *)arg;
  uchar          saddr[sizeof( struct sockaddr_in )];
  int            saddrlen = to_sockaddr( saddr, addr );
  if( sendto( _arg->sockfd,
              data,
              sz,
              MSG_DONTWAIT,
              (const struct sockaddr *)saddr,
              (socklen_t)saddrlen ) < 0 ) {
    FD_LOG_WARNING( ( "sendto failed: %s", strerror( errno ) ) );
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

static ulong
setup_scratch( fd_valloc_t valloc ) {
  ulong  smax   = 1UL << 31UL; /* 2 GiB scratch memory */
  ulong  sdepth = 1UL << 11UL; /* 2048 scratch frames, 1 MiB each */
  void * smem =
      fd_valloc_malloc( valloc, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax ) );
  void * fmem =
      fd_valloc_malloc( valloc, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( sdepth ) );
  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, smax, sdepth );
  return smax;
}

struct turbine_targs {
  int           tvu_fd;
  fd_replay_t * replay;
  fd_store_t *  store;
};
typedef struct turbine_targs turbine_targs_t;

static int
turbine_thread( FD_PARAM_UNUSED int argc, char ** argv ) {
  turbine_targs_t * args   = (turbine_targs_t *)argv;
  int               tvu_fd = args->tvu_fd;

  setup_scratch( args->replay->valloc );

#define VLEN 32U
  struct mmsghdr msgs[VLEN];
  struct iovec   iovecs[VLEN];
  uchar          bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar sockaddrs[VLEN][sizeof( struct sockaddr_in6 )]; /* sockaddr is smaller than sockaddr_in6 */
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
  while( FD_LIKELY( 1 /* !fd_tile_shutdown_flag */ ) ) {
    CLEAR_MSGS;
    int tvu_rc = recvmmsg( tvu_fd, msgs, VLEN, MSG_DONTWAIT, NULL );
    if( tvu_rc < 0 ) {
      if( errno == EINTR || errno == EWOULDBLOCK ) continue;
      FD_LOG_ERR( ( "recvmmsg failed: %s", strerror( errno ) ) );
      break;
    }

    for( uint i = 0; i < (uint)tvu_rc; ++i ) {
      fd_gossip_peer_addr_t from;
      from_sockaddr( &from, msgs[i].msg_hdr.msg_name );
      fd_shred_t const * shred = fd_shred_parse( bufs[i], msgs[i].msg_len );
      fd_replay_turbine_rx( args->replay, shred, msgs[i].msg_len );
    }
  }
  return 0;
}

struct repair_targ {
  int           repair_fd;
  fd_replay_t * replay;
};
typedef struct repair_targ repair_targ_t;

static int
repair_thread( FD_PARAM_UNUSED int argc, char ** argv ) {
  repair_targ_t * args      = (repair_targ_t *)argv;
  int             repair_fd = args->repair_fd;
  fd_repair_t *   repair    = args->replay->repair;

  setup_scratch( args->replay->valloc );

  struct mmsghdr msgs[VLEN];
  struct iovec   iovecs[VLEN];
  uchar          bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar sockaddrs[VLEN][sizeof( struct sockaddr_in6 )]; /* sockaddr is smaller than sockaddr_in6 */
  while( FD_LIKELY( 1 /* !fd_tile_shutdown_flag */ ) ) {
    long now = fd_log_wallclock();
    fd_repair_settime( repair, now );

    /* Loop repair */
    fd_repair_continue( repair );

    /* Read more packets */
    CLEAR_MSGS;
    int repair_rc = recvmmsg( repair_fd, msgs, VLEN, MSG_DONTWAIT, NULL );
    if( repair_rc < 0 ) {
      if( errno == EINTR || errno == EWOULDBLOCK ) continue;
      FD_LOG_ERR( ( "recvmmsg failed: %s", strerror( errno ) ) );
      break;
    }

    for( uint i = 0; i < (uint)repair_rc; ++i ) {
      fd_repair_peer_addr_t from;
      from_sockaddr( &from, msgs[i].msg_hdr.msg_name );
      fd_repair_recv_packet( repair, bufs[i], msgs[i].msg_len, &from );
    }
  }
  return 0;
}

struct gossip_targ {
  int           gossip_fd;
  fd_replay_t * replay;
  fd_gossip_t * gossip;
};
typedef struct gossip_targ gossip_targ_t;

static int
gossip_thread( FD_PARAM_UNUSED int argc, char ** argv ) {
  gossip_targ_t * _arg      = (gossip_targ_t *)argv;
  int             gossip_fd = _arg->gossip_fd;
  fd_gossip_t *   gossip    = _arg->gossip;

  setup_scratch( _arg->replay->valloc );

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

struct shredcap_targ {
  fd_replay_t * replay;
  const char *  shred_cap_fpath;
};
typedef struct shredcap_targ shredcap_targ_t;

static void *
shredcap_thread( void * arg ) {
  shredcap_targ_t * args = (shredcap_targ_t *)arg;
  fd_shred_cap_replay( args->shred_cap_fpath, args->replay );
  return 0;
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL, 0UL ) );

  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 0UL );
  const char * restore  = fd_env_strip_cmdline_cstr( &argc, &argv, "--restore", NULL, NULL );
  const char * incremental_snapshot =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--incremental-snapshot", NULL, NULL );
  const char * incremental_snapshot_url =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--incremental-snapshot-url", NULL, NULL );
  const char * gossip_peer_addr =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--gossip-peer-addr", NULL, NULL );
  const char * repair_peer_addr =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--repair-peer-addr", NULL, NULL );
  ushort gossip_port = fd_env_strip_cmdline_ushort( &argc, &argv, "--gossip-port", NULL, 9001 );
  ushort repair_port = fd_env_strip_cmdline_ushort( &argc, &argv, "--repair-port", NULL, 9002 );
  ushort tvu_port    = fd_env_strip_cmdline_ushort( &argc, &argv, "--tvu-port", NULL, 9003 );
  const char * repair_peer_id =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--repair-peer-id", NULL, NULL );
  const char * mode     = fd_env_strip_cmdline_cstr( &argc, &argv, "--mode", NULL, "archive" );
  const char * shredcap = fd_env_strip_cmdline_cstr( &argc, &argv, "--shredcap", NULL, NULL );

  FD_TEST( page_cnt );
  FD_TEST( restore );
  FD_TEST( gossip_peer_addr );
  FD_TEST( !incremental_snapshot || !incremental_snapshot_url );

  /**********************************************************************/
  /* wksp                                                               */
  /**********************************************************************/

  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                   page_cnt,
                   _page_sz,
                   numa_idx ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );
  FD_LOG_DEBUG( ( "Finish setup wksp" ) );

  /**********************************************************************/
  /* restore                                                            */
  /**********************************************************************/

  if( restore == NULL ) {
    FD_LOG_ERR( ( "For now, both live (archive shredcap) and sim (replay shredcap) need to restore "
                  "a funk for the snapshot." ) );
  }
  FD_LOG_NOTICE( ( "fd_wksp_restore %s", restore ) );
  int err = fd_wksp_restore( wksp, restore, TEST_CONSENSUS_MAGIC );
  if( err ) FD_LOG_ERR( ( "fd_wksp_restore failed: error %d", err ) );
  FD_LOG_DEBUG( ( "Finish restore funk" ) );

  /**********************************************************************/
  /* funk                                                               */
  /**********************************************************************/

  fd_wksp_tag_query_info_t funk_info;
  fd_funk_t *              funk     = NULL;
  ulong                    funk_tag = FD_FUNK_MAGIC;
  if( fd_wksp_tag_query( wksp, &funk_tag, 1, &funk_info, 1 ) > 0 ) {
    void * shmem = fd_wksp_laddr_fast( wksp, funk_info.gaddr_lo );
    funk         = fd_funk_join( shmem );
  }
  if( funk == NULL ) FD_LOG_ERR( ( "failed to join a funky" ) );

  /**********************************************************************/
  /* blockstore                                                         */
  /**********************************************************************/

  void * blockstore_mem = fd_wksp_alloc_laddr(
      wksp, fd_blockstore_align(), fd_blockstore_footprint(), TEST_CONSENSUS_MAGIC );
  fd_blockstore_t * blockstore = fd_blockstore_join( fd_blockstore_new(
      blockstore_mem, TEST_CONSENSUS_MAGIC, FD_BLOCKSTORE_MAGIC, 1 << 17, 1 << 13, 22 ) );
  FD_TEST( blockstore );

  /**********************************************************************/
  /* acc_mgr                                                            */
  /**********************************************************************/

  fd_acc_mgr_t acc_mgr[1];
  fd_acc_mgr_new( acc_mgr, funk );

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

  ulong  smax   = 1UL << 31UL; /* 2 GiB scratch memory */
  ulong  sdepth = 1UL << 11UL; /* 2048 scratch frames, 1 MiB each */
  void * smem =
      fd_valloc_malloc( valloc, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax ) );
  void * fmem =
      fd_valloc_malloc( valloc, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( sdepth ) );
  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, smax, sdepth );

  /**********************************************************************/
  /* bank_hash_cmp                                                      */
  /**********************************************************************/

  void * bank_hash_cmp_mem = fd_wksp_alloc_laddr(
      wksp, fd_bank_hash_cmp_align(), fd_bank_hash_cmp_footprint( 14 ), TEST_CONSENSUS_MAGIC );
  fd_bank_hash_cmp_t * bank_hash_cmp =
      fd_bank_hash_cmp_join( fd_bank_hash_cmp_new( bank_hash_cmp_mem, 14 ) );

  /**********************************************************************/
  /* epoch_ctx                                                          */
  /**********************************************************************/

  ulong                 vote_acc_max  = 2000000;
  uchar *               epoch_ctx_mem = fd_wksp_alloc_laddr( wksp,
                                               fd_exec_epoch_ctx_align(),
                                               fd_exec_epoch_ctx_footprint( vote_acc_max ),
                                               TEST_CONSENSUS_MAGIC );
  fd_exec_epoch_ctx_t * epoch_ctx =
      fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, vote_acc_max ) );
  FD_TEST( epoch_ctx );
  epoch_ctx->bank_hash_cmp = bank_hash_cmp;

  /**********************************************************************/
  /* forks                                                              */
  /**********************************************************************/

  ulong forks_max =
      fd_ulong_if( page_cnt > 64, fd_ulong_pow2_up( FD_DEFAULT_SLOTS_PER_EPOCH ), 1024 );
  FD_LOG_NOTICE( ( "forks_max: %lu", forks_max ) );
  FD_LOG_NOTICE( ( "fork footprint: %lu", fd_forks_footprint( forks_max ) ) );
  void * forks_mem = fd_wksp_alloc_laddr(
      wksp, fd_forks_align(), fd_forks_footprint( forks_max ), TEST_CONSENSUS_MAGIC );
  fd_forks_t * forks = fd_forks_join( fd_forks_new( forks_mem, forks_max, TEST_CONSENSUS_MAGIC ) );
  FD_TEST( forks );
  forks->acc_mgr    = acc_mgr;
  forks->blockstore = blockstore;
  forks->epoch_ctx  = epoch_ctx;
  forks->funk       = funk;
  forks->valloc     = valloc;

  /**********************************************************************/
  /* snapshot_slot_ctx                                                  */
  /**********************************************************************/

  fd_fork_t *          snapshot_fork = fd_fork_pool_ele_acquire( forks->pool );
  fd_exec_slot_ctx_t * snapshot_slot_ctx =
      fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &snapshot_fork->slot_ctx, valloc ) );
  FD_TEST( snapshot_slot_ctx );

  snapshot_slot_ctx->epoch_ctx = epoch_ctx;

  snapshot_slot_ctx->acc_mgr    = acc_mgr;
  snapshot_slot_ctx->blockstore = blockstore;
  snapshot_slot_ctx->valloc     = valloc;

  fd_runtime_recover_banks( snapshot_slot_ctx, 0 );

  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( snapshot_slot_ctx->epoch_ctx );
  char              incremental_snapshot_out[128] = { 0 };
  if( incremental_snapshot_url ) {
    FILE * fp;

    /* Open the command for reading. */
    char cmd[128];
    snprintf( cmd, sizeof( cmd ), "./shenanigans.sh %s", incremental_snapshot_url );
    FD_LOG_NOTICE( ( "cmd: %s", cmd ) );
    fp = popen( cmd, "r" );
    if( fp == NULL ) {
      printf( "Failed to run command\n" );
      exit( 1 );
    }

    /* Read the output a line at a time - output it. */
    if( !fgets( incremental_snapshot_out, sizeof( incremental_snapshot_out ) - 1, fp ) ) {
      FD_LOG_ERR( ( "failed to pass snapshot name" ) );
    }
    incremental_snapshot_out[strcspn( incremental_snapshot_out, "\n" )] = '\0';
    incremental_snapshot                                                = incremental_snapshot_out;
    pclose( fp );
  }
  if( incremental_snapshot ) {
    ulong i, j;
    FD_TEST( sscanf( incremental_snapshot, "incremental-snapshot-%lu-%lu", &i, &j ) == 2 );
    FD_TEST( i == snapshot_slot_ctx->slot_bank.slot );
    FD_TEST( epoch_bank );
    FD_TEST( fd_slot_to_epoch( &epoch_bank->epoch_schedule, i, NULL ) ==
             fd_slot_to_epoch( &epoch_bank->epoch_schedule, j, NULL ) );
    fd_snapshot_load( incremental_snapshot, snapshot_slot_ctx, 1, 1, FD_SNAPSHOT_TYPE_INCREMENTAL );
  }

  fd_runtime_cleanup_incinerator( snapshot_slot_ctx );
  ulong snapshot_slot = snapshot_slot_ctx->slot_bank.slot;
  FD_LOG_NOTICE( ( "snapshot_slot: %lu", snapshot_slot ) );

  bank_hash_cmp->slot                         = snapshot_slot + 1;
  snapshot_fork->slot                         = snapshot_slot;
  snapshot_slot_ctx->slot_bank.collected_fees = 0;
  snapshot_slot_ctx->slot_bank.collected_rent = 0;
  FD_TEST( !fd_runtime_sysvar_cache_load( snapshot_slot_ctx ) );

  fd_features_restore( snapshot_slot_ctx );
  fd_runtime_update_leaders( snapshot_slot_ctx, snapshot_slot_ctx->slot_bank.slot );
  fd_calculate_epoch_accounts_hash_values( snapshot_slot_ctx );

  fd_funk_start_write( funk );
  fd_bpf_scan_and_create_bpf_program_cache_entry( snapshot_slot_ctx, snapshot_slot_ctx->funk_txn );
  fd_funk_end_write( funk );
  snapshot_slot_ctx->leader =
      fd_epoch_leaders_get( fd_exec_epoch_ctx_leaders( epoch_ctx ), snapshot_slot );

  fd_blockstore_snapshot_insert( blockstore, &snapshot_slot_ctx->slot_bank );
  fd_fork_frontier_ele_insert( forks->frontier, snapshot_fork, forks->pool );
  FD_LOG_DEBUG( ( "Finish setup snapshot" ) );

  /**********************************************************************/
  /* ghost                                                              */
  /**********************************************************************/

  ulong        ghost_node_max = forks_max;
  ulong        ghost_vote_max = 1UL << 16;
  void *       ghost_mem      = fd_wksp_alloc_laddr( wksp,
                                          fd_ghost_align(),
                                          fd_ghost_footprint( ghost_node_max, ghost_vote_max ),
                                          TEST_CONSENSUS_MAGIC );
  fd_ghost_t * ghost          = fd_ghost_join(
      fd_ghost_new( ghost_mem, ghost_node_max, ghost_vote_max, TEST_CONSENSUS_MAGIC ) );
  FD_TEST( ghost );

  fd_slot_hash_t key = { .slot = snapshot_fork->slot,
                         .hash = snapshot_fork->slot_ctx.slot_bank.banks_hash };
  fd_ghost_leaf_insert( ghost, &key, NULL );
  FD_TEST( fd_ghost_node_map_ele_query( ghost->node_map, &key, NULL, ghost->node_pool ) );

  /**********************************************************************/
  /* bft                                                                */
  /**********************************************************************/

  void * bft_mem =
      fd_wksp_alloc_laddr( wksp, fd_bft_align(), fd_bft_footprint(), TEST_CONSENSUS_MAGIC );
  fd_bft_t * bft = fd_bft_join( fd_bft_new( bft_mem ) );

  bft->snapshot_slot = snapshot_slot;
  fd_bft_epoch_stake_update( bft, epoch_ctx );

  bft->acc_mgr    = acc_mgr;
  bft->blockstore = blockstore;
  bft->commitment = NULL;
  bft->forks      = forks;
  bft->ghost      = ghost;
  bft->valloc     = valloc;

  /**********************************************************************/
  /* replay                                                             */
  /**********************************************************************/

  void * replay_mem =
      fd_wksp_alloc_laddr( wksp, fd_replay_align(), fd_replay_footprint(), TEST_CONSENSUS_MAGIC );
  fd_replay_t * replay = fd_replay_join( fd_replay_new( replay_mem ) );
  FD_TEST( replay );

  replay->now = fd_log_wallclock();

  replay->smr           = snapshot_slot;
  replay->snapshot_slot = snapshot_slot;

  replay->acc_mgr    = acc_mgr;
  replay->bft        = bft;
  replay->blockstore = blockstore;
  replay->forks      = forks;
  replay->funk       = funk;
  replay->epoch_ctx  = epoch_ctx;
  replay->valloc     = valloc;

  /**********************************************************************/
  /* keys                                                               */
  /**********************************************************************/

  uchar private_key[32];
  FD_TEST( 32UL == getrandom( private_key, 32UL, 0 ) );
  fd_sha512_t sha[1];
  fd_pubkey_t public_key;
  FD_TEST( fd_ed25519_public_from_private( public_key.uc, private_key, sha ) );

  /**********************************************************************/
  /* shredcap                                                           */
  /**********************************************************************/

  /* do replay+shredcap or archive+live_data */

  replay->shred_cap = NULL;
  if( strcmp( mode, "replay" ) == 0 ) {
    FD_LOG_NOTICE( ( "test_consensus running in replay mode" ) );
    shredcap_targ_t shredcap_targ = { .shred_cap_fpath = shredcap, .replay = replay };
    pthread_t       shredcap_tid;
    FD_TEST( !pthread_create( &shredcap_tid, NULL, shredcap_thread, &shredcap_targ ) );
    goto run_replay;
  } else {
    if( shredcap ) {
      FD_LOG_NOTICE( ( "test_consensus running in live mode (with shredcap archive)" ) );
      replay->shred_cap = fopen( shredcap, "w" );
      FD_TEST( replay->shred_cap );
      replay->stable_slot_start = 0;
      replay->stable_slot_end   = 0;
    } else {
      FD_LOG_NOTICE( ( "test_consensus running in live mode (without shredcap archive)" ) );
    }
  }

  /**********************************************************************/
  /* repair                                                             */
  /**********************************************************************/

  void * repair_mem =
      fd_wksp_alloc_laddr( wksp, fd_repair_align(), fd_repair_footprint(), TEST_CONSENSUS_MAGIC );
  fd_repair_t * repair =
      fd_repair_join( fd_repair_new( repair_mem, TEST_CONSENSUS_MAGIC, valloc ) );

  fd_repair_config_t repair_config;
  repair_config.public_key  = &public_key;
  repair_config.private_key = private_key;
  char repair_addr[7]       = { 0 };
  snprintf( repair_addr, sizeof( repair_addr ), ":%u", repair_port );
  FD_TEST( resolve_hostport( repair_addr, &repair_config.intake_addr ) );
  repair_config.deliver_fun      = repair_deliver_fun;
  repair_config.send_fun         = repair_send_fun;
  repair_config.deliver_fail_fun = repair_deliver_fail_fun;
  repair_arg_t repair_arg        = { .replay = replay,
                                     .sockfd = create_socket( &repair_config.intake_addr ) };
  repair_config.fun_arg          = &repair_arg;
  repair_config.sign_fun         = sign_fun;
  repair_config.sign_arg         = &repair_config;

  FD_TEST( !fd_repair_set_config( repair, &repair_config ) );

  replay->repair = repair;

  /* optionally specify a repair peer identity to skip waiting for a contact info to come through */

  if( repair_peer_id ) {
    fd_pubkey_t _repair_peer_id;
    fd_base58_decode_32( repair_peer_id, _repair_peer_id.uc );
    fd_repair_peer_addr_t _repair_peer_addr = { 0 };
    if( FD_UNLIKELY(
            fd_repair_add_active_peer( replay->repair,
                                       resolve_hostport( repair_peer_addr, &_repair_peer_addr ),
                                       &_repair_peer_id ) ) ) {
      FD_LOG_ERR( ( "error adding repair active peer" ) );
    }
    fd_repair_add_sticky( replay->repair, &_repair_peer_id );
    fd_repair_set_permanent( replay->repair, &_repair_peer_id );
  }

  /**********************************************************************/
  /* turbine                                                            */
  /**********************************************************************/

  uchar *             data_shreds   = NULL;
  uchar *             parity_shreds = NULL;
  fd_fec_set_t *      fec_sets      = NULL;
  fd_fec_resolver_t * fec_resolver  = NULL;

  ulong depth          = 512;
  ulong partial_depth  = 1;
  ulong complete_depth = 1;
  ulong total_depth    = depth + partial_depth + complete_depth;
  data_shreds          = fd_wksp_alloc_laddr( wksp,
                                     128UL,
                                     FD_REEDSOL_DATA_SHREDS_MAX * total_depth * FD_SHRED_MAX_SZ,
                                     TEST_CONSENSUS_MAGIC );
  parity_shreds        = fd_wksp_alloc_laddr( wksp,
                                       128UL,
                                       FD_REEDSOL_PARITY_SHREDS_MAX * total_depth * FD_SHRED_MIN_SZ,
                                       TEST_CONSENSUS_MAGIC );
  fec_sets             = fd_wksp_alloc_laddr(
      wksp, alignof( fd_fec_set_t ), total_depth * sizeof( fd_fec_set_t ), TEST_CONSENSUS_MAGIC );

  ulong k = 0;
  ulong l = 0;
  /* TODO move this into wksp mem */
  for( ulong i = 0; i < total_depth; i++ ) {
    for( ulong j = 0; j < FD_REEDSOL_DATA_SHREDS_MAX; j++ ) {
      fec_sets[i].data_shreds[j] = &data_shreds[FD_SHRED_MAX_SZ * k++];
    }
    for( ulong j = 0; j < FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) {
      fec_sets[i].parity_shreds[j] = &parity_shreds[FD_SHRED_MIN_SZ * l++];
    }
  }
  FD_TEST( k == FD_REEDSOL_DATA_SHREDS_MAX * total_depth );

  ulong  done_depth       = 1024;
  void * fec_resolver_mem = fd_wksp_alloc_laddr(
      wksp,
      fd_fec_resolver_align(),
      fd_fec_resolver_footprint( depth, partial_depth, complete_depth, done_depth ),
      TEST_CONSENSUS_MAGIC );
  fec_resolver = fd_fec_resolver_join( fd_fec_resolver_new(
      fec_resolver_mem, depth, partial_depth, complete_depth, done_depth, fec_sets ) );

  FD_TEST( data_shreds );
  FD_TEST( parity_shreds );
  FD_TEST( fec_sets );
  FD_TEST( fec_resolver );

  replay->data_shreds   = data_shreds;
  replay->parity_shreds = parity_shreds;
  replay->fec_sets      = fec_sets;
  replay->fec_resolver  = fec_resolver;

  /**********************************************************************/
  /* gossip                                                             */
  /**********************************************************************/

  void * gossip_shmem =
      fd_wksp_alloc_laddr( wksp, fd_gossip_align(), fd_gossip_footprint(), TEST_CONSENSUS_MAGIC );
  fd_gossip_t * gossip =
      fd_gossip_join( fd_gossip_new( gossip_shmem, TEST_CONSENSUS_MAGIC, valloc ) );

  fd_gossip_config_t gossip_config;
  gossip_config.public_key  = &public_key;
  gossip_config.private_key = private_key;
  char gossip_addr[7]       = { 0 };
  snprintf( gossip_addr, sizeof( gossip_addr ), ":%u", gossip_port );
  FD_TEST( resolve_hostport( gossip_addr, &gossip_config.my_addr ) );
  gossip_config.shred_version             = 0;
  gossip_config.deliver_fun               = gossip_deliver_fun;
  gossip_deliver_arg_t gossip_deliver_arg = { .repair = repair, .bft = bft, .valloc = valloc };
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

  FD_LOG_NOTICE( ( "repair config intake addr %u %u",
                   repair_config.intake_addr.addr,
                   repair_config.intake_addr.port ) );
  fd_repair_update_addr( replay->repair, &repair_config.intake_addr, &repair_config.service_addr );
  FD_TEST( !fd_gossip_update_repair_addr( gossip, &repair_config.service_addr ) );
  fd_repair_settime( replay->repair, fd_log_wallclock() );
  fd_repair_start( replay->repair );

  /**********************************************************************/
  /* stake weights                                                      */
  /**********************************************************************/

  fd_vote_accounts_pair_t_mapnode_t * vote_accounts_pool =
      epoch_bank->stakes.vote_accounts.vote_accounts_pool;
  fd_vote_accounts_pair_t_mapnode_t * vote_accounts_root =
      epoch_bank->stakes.vote_accounts.vote_accounts_root;

  ulong stake_weights_cnt =
      fd_vote_accounts_pair_t_map_size( vote_accounts_pool, vote_accounts_root );
  ulong stake_weight_idx = 0;

  FD_SCRATCH_SCOPE_BEGIN {
    fd_stake_weight_t * stake_weights = fd_scratch_alloc(
        fd_stake_weight_align(), stake_weights_cnt * fd_stake_weight_footprint() );
    for( fd_vote_accounts_pair_t_mapnode_t const * n =
             fd_vote_accounts_pair_t_map_minimum_const( vote_accounts_pool, vote_accounts_root );
         n;
         n = fd_vote_accounts_pair_t_map_successor_const( vote_accounts_pool, n ) ) {
      fd_vote_state_versioned_t versioned;
      fd_bincode_decode_ctx_t   decode_ctx;
      decode_ctx.data    = n->elem.value.data;
      decode_ctx.dataend = n->elem.value.data + n->elem.value.data_len;
      decode_ctx.valloc  = fd_scratch_virtual();
      int rc             = fd_vote_state_versioned_decode( &versioned, &decode_ctx );
      if( FD_UNLIKELY( rc != FD_BINCODE_SUCCESS ) ) continue;
      fd_stake_weight_t * stake_weight = &stake_weights[stake_weight_idx];
      stake_weight->stake              = n->elem.stake;

      switch( versioned.discriminant ) {
      case fd_vote_state_versioned_enum_current:
        stake_weight->key = versioned.inner.current.node_pubkey;
        break;
      case fd_vote_state_versioned_enum_v0_23_5:
        stake_weight->key = versioned.inner.v0_23_5.node_pubkey;
        break;
      case fd_vote_state_versioned_enum_v1_14_11:
        stake_weight->key = versioned.inner.v1_14_11.node_pubkey;
        break;
      default:
        FD_LOG_DEBUG( ( "unrecognized vote_state_versioned type" ) );
        continue;
      }

      stake_weight_idx++;
    }

    fd_repair_set_stake_weights( repair, stake_weights, stake_weights_cnt );
    fd_gossip_set_stake_weights( gossip, stake_weights, stake_weights_cnt );
  }
  FD_SCRATCH_SCOPE_END;

  /**********************************************************************/
  /* tvu (turbine), repair, gossip threads                              */
  /**********************************************************************/

  fd_repair_peer_addr_t tvu_addr_   = { 0 };
  char                  tvu_addr[7] = { 0 };
  snprintf( tvu_addr, sizeof( tvu_addr ), ":%u", tvu_port );
  FD_TEST( resolve_hostport( tvu_addr, &tvu_addr_ ) );

  fd_repair_peer_addr_t tvu_fwd_addr     = { 0 };
  char                  tvu_fwd_addr_[7] = { 0 };
  snprintf( tvu_fwd_addr_, sizeof( tvu_fwd_addr_ ), ":%u", tvu_port + 1 );
  FD_TEST( resolve_hostport( tvu_fwd_addr_, &tvu_fwd_addr ) );

  /* initialize tvu */
  int tvu_sockfd = create_socket( &tvu_addr_ );
  FD_TEST( !fd_gossip_update_tvu_addr( gossip, &tvu_addr_, &tvu_fwd_addr ) );

  /**********************************************************************/
  /* start threads                                                      */
  /**********************************************************************/

  FD_LOG_NOTICE( ( "gossip: %s", gossip_addr ) );
  FD_LOG_NOTICE( ( "repair: %s", repair_addr ) );
  FD_LOG_NOTICE( ( "tvu: %s", tvu_addr ) );

  gossip_targ_t gossip_targ = { .gossip_fd = gossip_sockfd, .replay = replay, .gossip = gossip };
  FD_TEST( fd_tile_exec_new( 1, gossip_thread, 0, fd_type_pun( &gossip_targ ) ) );

  repair_targ_t repair_targ = { .repair_fd = repair_arg.sockfd, .replay = replay };
  FD_TEST( fd_tile_exec_new( 2, repair_thread, 0, fd_type_pun( &repair_targ ) ) );

  turbine_targs_t turbine_targ = { .tvu_fd = tvu_sockfd, .replay = replay };
  FD_TEST( fd_tile_exec_new( 3, turbine_thread, 0, fd_type_pun( &turbine_targ ) ) );

  /**********************************************************************/
  /* tpool                                                              */
  /**********************************************************************/

  ulong tile_cnt = fd_tile_cnt();
  FD_LOG_NOTICE( ( "tile_cnt: %lu", tile_cnt ) );
  fd_tpool_t * tpool = NULL;
  /* clang-format off */
  uchar tpool_mem[FD_TPOOL_FOOTPRINT( FD_TILE_MAX )]__attribute__((aligned(FD_TPOOL_ALIGN))) = { 0 };
  /* clang-format on */
  if( tile_cnt > 4 ) {
    tpool = fd_tpool_init( tpool_mem, tile_cnt );
    FD_TEST( tpool );
    if( tpool == NULL ) FD_LOG_ERR( ( "failed to create thread pool" ) );
    ulong   scratch_sz = fd_scratch_smem_footprint( 256 << 20 );
    uchar * scratch =
        fd_valloc_malloc( valloc, FD_SCRATCH_SMEM_ALIGN, scratch_sz * ( fd_tile_cnt() - 1 ) );
    for( ulong i = 4; i < tile_cnt; i++ ) {
      fd_tpool_t * worker =
          fd_tpool_worker_push( tpool, i, scratch + ( scratch_sz * ( i - 1 ) ), scratch_sz );
      FD_TEST( worker );
    }
    replay->max_workers = fd_tile_cnt() - 3;
    replay->tpool       = tpool;
  } else {
    replay->max_workers = 0;
    replay->tpool       = NULL;
  }

  /**********************************************************************/
  /* run replay                                                         */
  /**********************************************************************/

run_replay:

  while( 1 ) {
    long now    = fd_log_wallclock();
    replay->now = now;

    for( ulong slot = fd_replay_pending_iter_init( replay );
         ( slot = fd_replay_pending_iter_next( replay, now, slot ) ) != ULONG_MAX; ) {
      fd_fork_t * fork = fd_replay_slot_prepare( replay, slot );
      if( FD_LIKELY( fork ) ) {
        fd_replay_slot_execute( replay, slot, fork, NULL );
        if( slot > 64U ) replay->smr = fd_ulong_max( replay->smr, slot - 64U );
        replay->now = now = fd_log_wallclock();
      }
    }

    struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)1e6 };
    nanosleep( &ts, NULL );
  }

  if( replay->shred_cap ) fclose( replay->shred_cap );
  fd_halt();
  return 0;
}
