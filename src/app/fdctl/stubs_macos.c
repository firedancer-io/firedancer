#include "topology.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/topo/fd_topob.h"
#include "../../disco/topo/fd_cpu_topo.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../app/shared/commands/configure/configure.h"
#include "../../disco/net/fd_net_tile.h"
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>

struct fd_bonding_slave_iter {
  char   line[ 4096 ];
  char * saveptr;
  char * tok;
};
typedef struct fd_bonding_slave_iter fd_bonding_slave_iter_t;

/* Tile Stubs */

fd_topo_run_tile_t fd_tile_netlnk  = { .name = "netlnk"  };
fd_topo_run_tile_t fd_tile_net     = { .name = "net"     };
/* Redundant tiles now built in libfddev_shared or libfd_disco:pktgen, udpecho, sign, diag, plugin, resolh, store, bencho, benchg, benchs */

/* Netlink Topo Stubs */

ulong fd_netlink_topo_create( fd_topo_t * topo, char const * name ) { (void)topo; (void)name; return 0; }
void  fd_netlink_topo_join( fd_topo_t * topo, char const * name )   { (void)topo; (void)name; }

/* CPU Topo Stubs */

void fd_topo_cpus_init( fd_topo_cpus_t * cpus ) {
  memset( cpus, 0, sizeof(fd_topo_cpus_t) );
  cpus->cpu_cnt = 1;
  cpus->cpu[0].online = 1;
}

/* Keyload Stubs */

uchar * FD_FN_SENSITIVE
fd_keyload_read( int          key_fd,
                 char const * key_path,
                 uchar *      keypair ) {
  (void)key_path;
#define KEY_SZ 64UL
#define MAX_KEY_FILE_SZ 4096UL
  char * buf = (char *)malloc( MAX_KEY_FILE_SZ + 1 );
  if( !buf ) FD_LOG_ERR(( "malloc failed" ));

  long bytes_read = read( key_fd, buf, MAX_KEY_FILE_SZ );
  if( FD_UNLIKELY( bytes_read<=0 ) ) {
    free( buf );
    FD_LOG_ERR(( "reading key file failed" ));
  }
  close( key_fd );
  buf[ bytes_read ] = '\0';

  /* Simple manual parsing of [1,2,3...] */
  char * p = buf;
  while( *p && *p != '[' ) p++;
  if( !*p ) {
    free( buf );
    FD_LOG_ERR(( "invalid key file format (missing '[')" ));
  }
  p++;

  for( ulong i=0; i<KEY_SZ; i++ ) {
    while( *p && (*p==' ' || *p=='\n' || *p=='\r' || *p=='\t' || *p==',') ) p++;
    if( !*p ) {
      free( buf );
      FD_LOG_ERR(( "invalid key file format (truncated at %lu)", i ));
    }
    
    char * endptr;
    unsigned long val = strtoul( p, &endptr, 10 );
    if( p==endptr ) {
      free( buf );
      FD_LOG_ERR(( "invalid key file format (nan at %lu)", i ));
    }
    keypair[ i ] = (uchar)val;
    p = endptr;
  }

  free( buf );
  return keypair;
#undef MAX_KEY_FILE_SZ
#undef KEY_SZ
}

uchar * FD_FN_SENSITIVE
fd_keyload_load( char const * key_path,
                 int          public_key_only ) {
  int fd = open( key_path, O_RDONLY );
  if( FD_UNLIKELY( fd==-1 ) ) FD_LOG_ERR(( "failed to open key file `%s` (%i-%s)", key_path, errno, fd_io_strerror( errno ) ));

  /* Use a large enough buffer that is correctly aligned for the public key slice */
  static uchar key_buffer[ 1024 ] __attribute__((aligned(128)));
  memset( key_buffer, 0, sizeof(key_buffer) );

  fd_keyload_read( fd, key_path, key_buffer );

  if( public_key_only ) {
    static uchar pubkey[ 32 ] __attribute__((aligned(32)));
    memcpy( pubkey, key_buffer + 32, 32 );
    return pubkey;
  }
  return key_buffer;
}

void FD_FN_SENSITIVE
fd_keyload_unload( uchar const * key,
                   int           public_key_only ) {
  (void)key; (void)public_key_only;
}

void * FD_FN_SENSITIVE
fd_keyload_alloc_protected_pages( ulong page_cnt, ulong guard_page_cnt ) {
  ulong page_sz = 16384UL; /* macOS page size */
  ulong total_sz = (2UL*guard_page_cnt + page_cnt) * page_sz;
  void * pages = mmap( NULL, total_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0UL );
  if( FD_UNLIKELY( pages==MAP_FAILED ) ) FD_LOG_ERR(( "mmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  uchar * middle_pages = (uchar *)pages + guard_page_cnt*page_sz;
  mprotect( pages, guard_page_cnt*page_sz, PROT_NONE );
  mprotect( middle_pages + page_cnt*page_sz, guard_page_cnt*page_sz, PROT_NONE );
  return middle_pages;
}

/* Keyswitch Stubs */

ulong fd_keyswitch_align( void ) { return FD_KEYSWITCH_ALIGN; }
ulong fd_keyswitch_footprint( void ) { return FD_KEYSWITCH_FOOTPRINT; }
fd_keyswitch_t * fd_keyswitch_join( void * shks ) { return (fd_keyswitch_t *)shks; }
void * fd_keyswitch_leave( fd_keyswitch_t const * ks ) { return (void *)ks; }
void * fd_keyswitch_new( void * shmem, ulong state ) { (void)state; return shmem; }

/* Keyguard Client Stubs */

void * fd_keyguard_client_new( void * shmem, fd_frag_meta_t * request_mcache, uchar * request_dcache, fd_frag_meta_t * response_mcache, uchar * response_dcache, ulong request_mtu ) {
  (void)shmem; (void)request_mcache; (void)request_dcache; (void)response_mcache; (void)response_dcache; (void)request_mtu;
  return shmem;
}

void fd_keyguard_client_sign( fd_keyguard_client_t * client, uchar * signature, uchar const * sign_data, ulong sign_data_len, int sign_type ) {
  (void)client; (void)signature; (void)sign_data; (void)sign_data_len; (void)sign_type;
}

int fd_keyguard_payload_authorize( fd_keyguard_authority_t const * authority, uchar const * data, ulong sz, int role, int sign_type ) {
  (void)authority; (void)data; (void)sz; (void)role; (void)sign_type;
  return 0;
}

/* Agave/Ext Bank Stubs */

int fd_ext_bank_execute_and_commit_bundle( void const * bank, void * txns, ulong txn_cnt, int * out_transaction_err, uint * actual_execution_cus, uint * actual_acct_data_cus, ulong * out_timestamps, ulong * out_tips ) {
  (void)bank; (void)txns; (void)txn_cnt; (void)out_transaction_err; (void)actual_execution_cus; (void)actual_acct_data_cus; (void)out_timestamps; (void)out_tips;
  return 0;
}

int fd_ext_bank_load_account( void const * bank, int fixed_root, uchar const * addr, uchar * owner, uchar * data, ulong * data_sz ) {
  (void)bank; (void)fixed_root; (void)addr; (void)owner; (void)data; (void)data_sz;
  return -1;
}

/* Configure Stage Stubs */

configure_stage_t fd_cfg_stage_hugetlbfs        = { .name = "hugetlbfs"        };
configure_stage_t fd_cfg_stage_sysctl           = { .name = "sysctl"           };
configure_stage_t fd_cfg_stage_hyperthreads     = { .name = "hyperthreads"     };
configure_stage_t fd_cfg_stage_bonding          = { .name = "bonding"          };
configure_stage_t fd_cfg_stage_ethtool_channels = { .name = "ethtool-channels" };
configure_stage_t fd_cfg_stage_ethtool_offloads = { .name = "ethtool-offloads" };
configure_stage_t fd_cfg_stage_ethtool_loopback = { .name = "ethtool-loopback" };
configure_stage_t fd_cfg_stage_snapshots        = { .name = "snapshots"        };
/* Redundant stages now built: keys, kill, genesis, blockstore */

/* Action Stubs */

/* Redundant actions now built: configure, bench, pktgen, udpecho */

/* Bonding Stubs */

fd_bonding_slave_iter_t * fd_bonding_slave_iter_init( fd_bonding_slave_iter_t * iter, char const * device ) { (void)device; return iter; }
int    fd_bonding_slave_iter_done( fd_bonding_slave_iter_t const * iter ) { (void)iter; return 1; }
void   fd_bonding_slave_iter_next( fd_bonding_slave_iter_t * iter ) { (void)iter; }
char const * fd_bonding_slave_iter_ele( fd_bonding_slave_iter_t const * iter ) { (void)iter; return NULL; }
int    fd_bonding_is_master( char const * device ) { (void)device; return 0; }

/* Admin RPC Stubs */

int fd_ext_admin_rpc_set_identity( uchar const * identity_keypair, int is_ephemeral ) {
  (void)identity_keypair; (void)is_ephemeral;
  return 0;
}

/* Vinyl Stubs */

void fd_vinyl_mmio( void ) {}
void fd_vinyl_mmio_sz( void ) {}
void * fd_vinyl_rq_join( void * shrq ) { return shrq; }
void * fd_vinyl_rq_leave( void * rq ) { return rq; }
char const * fd_vinyl_strerror( int err ) { (void)err; return "Not implemented on macOS"; }
void fd_vinyl_bstream_pair_test( void ) {}
void fd_vinyl_bstream_zpad_test( void ) {}

/* Other Stubs */

void fd_topo_install_xdp_simple( void * topo, void * addr ) { (void)topo; (void)addr; }
