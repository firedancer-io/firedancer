#include "fd_backtest_rocksdb.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_pcapng.h"
#include "../../util/net/fd_ip4.h"
#include "fd_shredcap.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../flamenco/gossip/fd_gossip_types.h"
#include "fd_libc_zstd.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

/* Hardcoded constants */

#define IF_IDX_NET      (0)
#define IF_IDX_SHREDCAP (1)
#define SHRED_PORT      ((ushort)8003)

static int
usage( int rc ) {
  fputs(
    "\n"
    "Usage: fd_blockstore2shredcap --rocksdb <path> --out <path>\n"
    "\n"
    "Extract rooted blocks from Agave RocksDB.\n"
    "Produces shredcap 0.1 (pcapng) file containing shreds and bank hashes.\n"
    "\n"
    "  --rocksdb <path>  Agave RocksDB directory\n"
    "  --out     <path>  File path to new shredcap file (fails if file already exists)\n"
#   if FD_HAS_ZSTD
    "  --zstd            Output compressed .pcapng.zst stream instead of raw pcapng\n"
    "  --zstd-level      Zstandard compression level\n"
#   endif
    "\n",
    stderr
  );
  return rc;
}

static void
write_bank_hash( FILE *      pcap,
                 ulong       slot,
                 ulong       shred_cnt,
                 uchar const bank_hash[32] ) {
  struct __attribute__((packed)) {
    uint type;
    fd_shredcap_bank_hash_v0_t bank_hash_rec;
  } packet;
  memset( &packet, 0, sizeof(packet) );

  packet.type = FD_SHREDCAP_TYPE_BANK_HASH_V0;
  fd_shredcap_bank_hash_v0_t * bank_hash_rec = &packet.bank_hash_rec;
  bank_hash_rec->slot           = slot;
  bank_hash_rec->data_shred_cnt = shred_cnt;
  memcpy( bank_hash_rec->bank_hash, bank_hash, 32UL );

  fd_pcapng_fwrite_pkt1( pcap, &packet, sizeof(packet), NULL, 0UL, IF_IDX_SHREDCAP, 0L );
}

static void
write_shred( FILE *       pcap,
             void const * shred ) {
  ulong shred_sz = fd_shred_sz( shred );
  FD_TEST( shred_sz<=FD_SHRED_MAX_SZ );

  struct __attribute__((packed)) {
    fd_ip4_hdr_t ip4;
    fd_udp_hdr_t udp;
    uchar shred[ FD_SHRED_MAX_SZ ];
  } packet;

  packet.ip4 = (fd_ip4_hdr_t) {
    .verihl       = FD_IP4_VERIHL( 4, 5 ),
    .tos          = 0,
    .net_tot_len  = fd_ushort_bswap( (ushort)( 28+shred_sz ) ),
    .net_id       = 0,
    .net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF ),
    .ttl          = 64,
    .protocol     = FD_IP4_HDR_PROTOCOL_UDP,
    .check        = 0,
    .saddr        = FD_IP4_ADDR( 127,0,0,1 ),
    .daddr        = FD_IP4_ADDR( 127,0,0,1 ),
  };
  packet.ip4.check = fd_ip4_hdr_check_fast( &packet.ip4 );
  packet.udp = (fd_udp_hdr_t) {
    .net_sport = fd_ushort_bswap( 42424 ),
    .net_dport = fd_ushort_bswap( SHRED_PORT ),
    .net_len   = fd_ushort_bswap( (ushort)( 8+shred_sz ) ),
    .check     = 0,
  };
  fd_memcpy( packet.shred, shred, shred_sz );

  struct __attribute__((packed)) {
    ushort option_type;
    ushort option_sz;
    uint   pen;
    ushort magic;
    ushort gossip_tag;
  } option = {
    .option_type = 2989,   /* Custom Option containing binary octects, copyable */
    .option_sz   = 8,
    .pen         = 31592,  /* Jump Trading, LLC */
    .magic       = 0x4071, /* SOL! */
    .gossip_tag  = FD_CONTACT_INFO_SOCKET_TVU
  };

  fd_pcapng_fwrite_pkt1( pcap, &packet, 28UL+shred_sz, &option, sizeof(option), IF_IDX_NET, 0L );
}

int
main( int     argc,
      char ** argv ) {
  if( fd_env_strip_cmdline_contains( &argc, &argv, "--help" ) ) return usage( 0 );

  char const * rocksdb_path = fd_env_strip_cmdline_cstr( &argc, &argv, "--rocksdb", NULL, NULL );
  char const * out_path     = fd_env_strip_cmdline_cstr( &argc, &argv, "--out",     NULL, NULL );
  char const * out_short    = fd_env_strip_cmdline_cstr( &argc, &argv, "--o",       NULL, NULL );
  if( !out_path ) out_path = out_short;

  int use_zstd   = fd_env_strip_cmdline_contains( &argc, &argv, "--zstd"                );
  int zstd_level = fd_env_strip_cmdline_int     ( &argc, &argv, "--zstd-level", NULL, 3 );
# if !FD_HAS_ZSTD
  if( use_zstd ) FD_LOG_ERR(( "This build does not support ZSTD compression" ));
  (void)zstd_level;
# endif

  if( FD_UNLIKELY( !rocksdb_path ) ) {
    fputs( "Error: --rocksdb not specified\n", stderr );
    return usage( 1 );
  }
  if( FD_UNLIKELY( !out_path ) ) {
    fputs( "Error: --out not specified\n", stderr );
    return usage( 1 );
  }

  fd_boot( &argc, &argv );

  void * rocks_mem = aligned_alloc( fd_backtest_rocksdb_align(), fd_backtest_rocksdb_footprint() );
  if( FD_UNLIKELY( !rocks_mem ) ) FD_LOG_ERR(( "out of memory" ));
  fd_backtest_rocksdb_t * rocksdb = fd_backtest_rocksdb_join( fd_backtest_rocksdb_new( rocks_mem, rocksdb_path ) );
  if( FD_UNLIKELY( !rocksdb ) ) FD_LOG_ERR(( "failed to open RocksDB at %s", rocksdb_path ));
  fd_backtest_rocksdb_init( rocksdb, 0UL );

  int out_fd = open( out_path, O_WRONLY|O_CREAT|O_EXCL, 0644 );
  if( FD_UNLIKELY( out_fd<0 ) ) FD_LOG_ERR(( "failed to create file %s (%i-%s)", out_path, errno, fd_io_strerror( errno ) ));
  FILE * out = fdopen( out_fd, "wb" );
  if( FD_UNLIKELY( !out ) ) FD_LOG_ERR(( "fdopen failed on %s (%i-%s)", out_path, errno, fd_io_strerror( errno ) ));

# if FD_HAS_ZSTD
  if( use_zstd ) {
    out = fd_zstd_wstream_open( out, zstd_level );
    if( FD_UNLIKELY( !out ) ) FD_LOG_ERR(( "failed to initialize ZSTD compression" ));
  }
# endif

  /* Write pcapng header */
  {
    fd_pcapng_shb_opts_t shb_opts;
    fd_pcapng_shb_defaults( &shb_opts );
    if( FD_UNLIKELY( !fd_pcapng_fwrite_shb( &shb_opts, out ) ) ) FD_LOG_ERR(( "pcap write error" ));
  }
  uint idb_cnt = 0U;
  {
    fd_pcapng_idb_opts_t idb_opts = {
      .name     = "lo",
      .ip4_addr = { 127,0,0,1 }
    };
    if( FD_UNLIKELY( !fd_pcapng_fwrite_idb( FD_PCAPNG_LINKTYPE_IPV4, &idb_opts, out ) ) ) FD_LOG_ERR(( "pcap write error" ));
    FD_TEST( idb_cnt++==IF_IDX_NET );
  }
  {
    fd_pcapng_idb_opts_t idb_opts = {
      .name = "shredcap0",
    };
    if( FD_UNLIKELY( !fd_pcapng_fwrite_idb( FD_PCAPNG_LINKTYPE_USER0, &idb_opts, out ) ) ) FD_LOG_ERR(( "pcap write error" ));
    FD_TEST( idb_cnt++==IF_IDX_SHREDCAP );
  }

  ulong slot_cnt = 0UL;
  for( ;; slot_cnt++ ) {

    ulong root_slot;
    ulong shred_cnt;
    int root_ok = fd_backtest_rocksdb_next_root_slot( rocksdb, &root_slot, &shred_cnt );
    if( !root_ok ) break;
    uchar const * bank_hash = fd_backtest_rocksdb_bank_hash( rocksdb, root_slot );
    if( FD_UNLIKELY( !bank_hash ) ) FD_LOG_ERR(( "failed to extract bank hash for root slot %lu", root_slot ));

    write_bank_hash( out, root_slot, shred_cnt, bank_hash );

    for( ulong i=0UL; i<shred_cnt; i++ ) {
      void const * shred = fd_backtest_rocksdb_shred( rocksdb, root_slot, i );
      if( FD_UNLIKELY( !shred ) ) {
        FD_LOG_WARNING(( "missing shred %lu for slot %lu", i, root_slot ));
        break;
      }
      write_shred( out, shred );
    }

  }

  long off = ftell( out );
  FD_LOG_NOTICE(( "%s: wrote %lu slots, %ld bytes", out_path, slot_cnt, off ));

  /* FIXME missing destructor for backtest_rocksdb */
  if( FD_UNLIKELY( 0!=fclose( out ) ) ) {
    FD_LOG_ERR(( "fclose failed on %s (%i-%s), output file may be corrupt", out_path, errno, fd_io_strerror( errno ) ));
  }
  free( rocks_mem );

  fd_halt();
  return 0;
}
