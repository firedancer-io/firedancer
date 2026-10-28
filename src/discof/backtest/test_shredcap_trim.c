#include "fd_shredcap_trim.h"
#include "fd_backtest_src.h"
#include "fd_shredcap.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_pcapng.h"
#include "../../util/net/fd_udp.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <zstd.h>

/* A shred in an IPv4 UDP packet, as blockstore2shredcap writes it */

struct __attribute__((packed)) test_pkt {
  fd_ip4_hdr_t ip4;
  fd_udp_hdr_t udp;
  uchar        shred[ FD_SHRED_MIN_SZ ];
};
typedef struct test_pkt test_pkt_t;

struct __attribute__((packed)) test_bank_hash {
  uint                       type;
  fd_shredcap_bank_hash_v0_t rec;
};

struct __attribute__((packed)) test_root_slot {
  uint                       type;
  fd_shredcap_root_slot_v0_t rec;
};

static void
write_shreds( FILE * file,
              ulong  slot ) {
  for( uint idx=0U; idx<2U; idx++ ) {
    test_pkt_t pkt = {
      .ip4 = {
        .verihl      = FD_IP4_VERIHL( 4, 5 ),
        .net_tot_len = fd_ushort_bswap( (ushort)sizeof(test_pkt_t) ),
        .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
        .saddr       = FD_IP4_ADDR( 127, 0, 0, 1 ),
        .daddr       = FD_IP4_ADDR( 127, 0, 0, 1 )
      },
      .udp = {
        .net_len = fd_ushort_bswap( (ushort)( sizeof(fd_udp_hdr_t)+FD_SHRED_MIN_SZ ) )
      }
    };
    fd_shred_t * shred = (fd_shred_t *)fd_type_pun( pkt.shred );
    shred->variant         = 0xa5;
    shred->slot            = slot;
    shred->idx             = idx;
    shred->data.parent_off = 1;
    shred->data.size       = (ushort)FD_SHRED_MIN_SZ;
    FD_TEST( 1UL==fd_pcapng_fwrite_pkt1( file, &pkt, sizeof(test_pkt_t), NULL, 0UL, 0U, 0L ) );
  }
}

static void
write_bank_hash( FILE * file,
                 ulong  slot ) {
  struct test_bank_hash rec = { .type=FD_SHREDCAP_TYPE_BANK_HASH_V0, .rec={ .slot=slot, .data_shred_cnt=2UL } };
  FD_TEST( 1UL==fd_pcapng_fwrite_pkt1( file, &rec, sizeof(rec), NULL, 0UL, 1U, 0L ) );
}

static void
write_root_slot( FILE * file,
                 ulong  slot ) {
  struct test_root_slot rec = { .type=FD_SHREDCAP_TYPE_ROOT_SLOT_V0, .rec={ .slot=slot } };
  FD_TEST( 1UL==fd_pcapng_fwrite_pkt1( file, &rec, sizeof(rec), NULL, 0UL, 1U, 0L ) );
}

/* write_capture writes a shredcap where slots 2 to 5, 11 and 12 have
   two shreds, a bank hash record and a root record.  Slot 0 has only
   a root record, slot 1 has no root record, and slot 10 has only
   shreds.  The last packet is too short to be a shred. */

static void
write_capture( char const * path ) {
  FILE * file = fopen( path, "wb" );
  FD_TEST( file );

  FD_TEST( 1UL==fd_shredcap_fwrite_hdr( file ) );

  write_root_slot( file, 0UL );
  write_shreds   ( file, 1UL );
  write_bank_hash( file, 1UL );
  for( ulong slot=2UL; slot<=5UL; slot++ ) {
    write_shreds   ( file, slot );
    write_bank_hash( file, slot );
    write_root_slot( file, slot );
  }
  write_shreds   ( file, 10UL );
  write_shreds   ( file, 11UL );
  write_bank_hash( file, 11UL );
  write_root_slot( file, 11UL );
  write_shreds   ( file, 12UL );
  write_bank_hash( file, 12UL );
  write_root_slot( file, 12UL );

  struct __attribute__((packed)) {
    fd_ip4_hdr_t ip4;
    fd_udp_hdr_t udp;
  } bad_pkt = {
    .ip4 = { .verihl=FD_IP4_VERIHL( 4, 5 ), .protocol=FD_IP4_HDR_PROTOCOL_UDP }
  };
  FD_TEST( 1UL==fd_pcapng_fwrite_pkt1( file, &bad_pkt, sizeof(bad_pkt), NULL, 0UL, 0U, 0L ) );

  FD_TEST( 0==fclose( file ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char in_path [] = "/tmp/test_shredcap_trim_in.XXXXXX";
  char out_path[] = "/tmp/test_shredcap_trim_out.XXXXXX";
  int  in_fd      = mkstemp( in_path  );
  int  out_fd     = mkstemp( out_path );
  FD_TEST( in_fd >=0 );
  FD_TEST( out_fd>=0 );
  FD_TEST( 0==close( in_fd  ) );
  FD_TEST( 0==close( out_fd ) );
  write_capture( in_path );

  fd_shredcap_trim_stats_t stats;

  /* Reading stops at slot 10, before the bad packet */
  FD_TEST( 0==fd_shredcap_trim( in_path, out_path, 2UL, 9UL, &stats ) );
  FD_TEST( stats.first_slot==1UL );
  FD_TEST( stats.last_slot==5UL );

  /* Each refusal logs a warning */
  int log_level_stderr = fd_log_level_stderr();
  fd_log_level_stderr_set( 4 );
  FD_TEST( -1==fd_shredcap_trim( in_path, out_path, 7UL, 9UL, &stats ) );
  FD_TEST( -1==fd_shredcap_trim( in_path, out_path, 0UL, 4UL, &stats ) );
  FD_TEST( -1==fd_shredcap_trim( in_path, out_path, 1UL, 4UL, &stats ) );
  FD_TEST( -1==fd_shredcap_trim( in_path, out_path, 2UL, 10UL, &stats ) );
  FD_TEST( -1==fd_shredcap_trim( in_path, out_path, 2UL, 11UL, &stats ) );
  FD_TEST( -1==fd_shredcap_trim( in_path, out_path, 11UL, 12UL, &stats ) );
  FD_TEST( -1==fd_shredcap_trim( "/dev/null", out_path, 2UL, 4UL, &stats ) );
  fd_log_level_stderr_set( log_level_stderr );

  FD_TEST( 0==fd_shredcap_trim( in_path, out_path, 2UL, 4UL, &stats ) );
  FD_TEST( stats.last_slot==4UL );
  FD_TEST( stats.shred_cnt==6UL );
  FD_TEST( stats.bank_hash_cnt==3UL );

  /* The backtest reads exactly slots 2 to 4 from the output */
  fd_backt_src_t * src = fd_backtest_src_create( &(fd_backtest_src_opts_t){ .format="auto", .path=out_path } );
  FD_TEST( src );
  uchar buf[ FD_SHRED_MAX_SZ ];
  for( ulong i=0UL; i<6UL; i++ ) {
    ulong sz = fd_backtest_src_shred( src, buf, sizeof(buf) );
    FD_TEST( sz==FD_SHRED_MIN_SZ );
    fd_shred_t const * shred = fd_shred_parse( buf, sz, FD_SHRED_BLK_MAX );
    FD_TEST( shred );
    FD_TEST( shred->slot==2UL+i/2UL );
  }
  FD_TEST( fd_backtest_src_shred( src, buf, sizeof(buf) )==ULONG_MAX );
  for( ulong slot=2UL; slot<=5UL; slot++ ) {
    fd_backt_slot_info_t info;
    FD_TEST( fd_backtest_src_slot_info( src, &info, slot ) );
    FD_TEST( info.rooted       ==(slot<=4UL) );
    FD_TEST( info.bank_hash_set==(slot<=4UL) );
  }
  fd_backtest_src_destroy( src );

  /* The output is zstd compressed and can be trimmed again */
  FILE * file = fopen( out_path, "rb" );
  FD_TEST( file );
  uint magic = 0U;
  FD_TEST( 1UL==fread( &magic, sizeof(uint), 1UL, file ) );
  FD_TEST( 0==fclose( file ) );
  FD_TEST( magic==ZSTD_MAGICNUMBER );
  FD_TEST( 0==fd_shredcap_trim( out_path, in_path, 3UL, 4UL, &stats ) );
  FD_TEST( stats.shred_cnt==4UL );
  FD_TEST( stats.bank_hash_cnt==2UL );

  FD_TEST( 0==unlink( in_path  ) );
  FD_TEST( 0==unlink( out_path ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
