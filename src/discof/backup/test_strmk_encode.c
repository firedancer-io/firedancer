/* Round trips the boot stream archive writer through fd_ssparse, which
   is what a booting peer parses it with, and exercises the sent set a
   stream dedups its accounts with. */

#define _GNU_SOURCE
#define FD_TILE_TEST
#pragma GCC diagnostic ignored "-Wunused-function"
#include "fd_strmk_tile.c"

#include "../restore/utils/fd_ssparse.h"
#include "../../util/tmpl/fd_unit_test.c"
#include <sys/mman.h>

#define TEST_SLOT_X (100UL)
#define TEST_SLOT   (103UL)

/* One account the test writes into an appendvec. */

struct test_acc {
  fd_pubkey_t key;
  ulong       lamports;
  int         executable;
  fd_pubkey_t owner;
  ulong       data_len;
  uchar *     data;
};

typedef struct test_acc test_acc_t;

static fd_strmk_t     ctx[1];
static strmk_stream_t stream[1];

/* env_create hands the archive writer a file to write into and the
   buffers it compresses through. */

static void
env_create( void ) {
  memset( ctx,    0, sizeof(fd_strmk_t)     );
  memset( stream, 0, sizeof(strmk_stream_t) );

  ctx->comp = aligned_alloc( 16UL, STRMK_COMP_BUF_SZ );
  FD_TEST( ctx->comp );

  stream->raw = mmap( NULL, STRMK_RAW_BUF_SZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( stream->raw!=MAP_FAILED );

  ulong zst_sz = ZSTD_estimateCStreamSize( FD_BACKUP_ZSTD_LEVEL );
  void * zst_mem = aligned_alloc( 64UL, fd_ulong_align_up( zst_sz, 64UL ) );
  FD_TEST( zst_mem );
  stream->zst = ZSTD_initStaticCStream( zst_mem, zst_sz );
  FD_TEST( stream->zst );
  FD_TEST( !ZSTD_isError( ZSTD_CCtx_setParameter( stream->zst, ZSTD_c_compressionLevel, FD_BACKUP_ZSTD_LEVEL ) ) );

  stream->fd     = memfd_create( "boot-stream", 0U );
  FD_TEST( stream->fd>=0 );
  stream->slot_x = TEST_SLOT_X;
}

static void
env_destroy( void ) {
  FD_TEST( !close( stream->fd ) );
  free( ZSTD_freeCStream( stream->zst )==0UL ? NULL : NULL );
  FD_TEST( !munmap( stream->raw, STRMK_RAW_BUF_SZ ) );
}

/* write_entry writes one tar entry of content_sz bytes the caller has
   already staged behind the tar header. */

static void
write_entry( char const * name,
             ulong        content_sz ) {
  zip_tar_hdr( stream, name, content_sz );
  zip_entry( ctx, stream, content_sz );
}

/* write_fixed writes the entries a peer needs before any appendvec.
   Their content does not matter here, only that the parser accepts the
   archive up to the accounts. */

static void
write_fixed( void ) {
  memcpy( stream->raw + sizeof(fd_tar_meta_t), "1.2.0", 5UL );
  write_entry( "version", 5UL );

  char name[ FD_TAR_NAME_SZ ];
  FD_TEST( fd_cstr_printf_check( name, sizeof(name), NULL, "snapshots/%lu/%lu", TEST_SLOT_X, TEST_SLOT_X ) );
  memset( stream->raw + sizeof(fd_tar_meta_t), 0xa5, 777UL );
  write_entry( name, 777UL );

  memset( stream->raw + sizeof(fd_tar_meta_t), 0x5a, 333UL );
  write_entry( "snapshots/status_cache", 333UL );
}

/* read_back decompresses the whole archive file.  Each tar entry is
   its own Zstandard frame, so this also proves the frames concatenate
   into one stream. */

static uchar *
read_back( ulong * out_sz ) {
  FD_TEST( -1!=lseek( stream->fd, 0L, SEEK_SET ) );
  ulong   comp_max = stream->file_sz;
  uchar * comp     = malloc( comp_max );
  FD_TEST( comp );
  ulong rd;
  FD_TEST( !fd_io_read( stream->fd, comp, comp_max, comp_max, &rd ) );
  FD_TEST( rd==comp_max );

  ulong   raw_max = 64UL<<20;
  uchar * raw     = malloc( raw_max );
  FD_TEST( raw );
  ZSTD_DStream * dst = ZSTD_createDStream();
  FD_TEST( dst );
  ZSTD_inBuffer  in  = { .src = comp, .size = comp_max, .pos = 0UL };
  ZSTD_outBuffer out = { .dst = raw,  .size = raw_max,  .pos = 0UL };
  while( in.pos<in.size ) {
    ulong ret = ZSTD_decompressStream( dst, &out, &in );
    FD_TEST( !ZSTD_isError( ret ) );
  }
  ZSTD_freeDStream( dst );
  free( comp );
  *out_sz = out.pos;
  return raw;
}

/* expect_accounts parses the archive and checks that the appendvec of
   slot holds exactly the given accounts, in order. */

static void
expect_accounts( ulong              slot,
                 test_acc_t const * acc,
                 ulong              acc_cnt ) {
  ulong   raw_sz;
  uchar * raw = read_back( &raw_sz );

  fd_ssparse_t ssparse[1];
  FD_TEST( fd_ssparse_init( ssparse ) );
  fd_ssparse_batch_enable( ssparse, 0 );

  ulong off      = 0UL;
  ulong acc_idx  = 0UL;
  ulong data_off = 0UL;
  int   in_vec   = 0;
  int   vec_done = 0;
  for(;;) {
    fd_ssparse_advance_result_t res[1];
    int adv = fd_ssparse_advance( ssparse, raw+off, raw_sz-off, res );
    FD_TEST( adv!=FD_SSPARSE_ADVANCE_ERROR );
    off += res->bytes_consumed;
    if( FD_UNLIKELY( adv==FD_SSPARSE_ADVANCE_AGAIN && off>=raw_sz ) ) break;

    switch( adv ) {
    case FD_SSPARSE_ADVANCE_APPENDVEC:
      FD_TEST( res->appendvec.slot==slot );
      FD_TEST( res->appendvec.id==0UL   );
      fd_ssparse_appendvec_parse( ssparse );
      in_vec = 1;
      break;
    case FD_SSPARSE_ADVANCE_ACCOUNT_HEADER: {
      FD_TEST( in_vec );
      FD_TEST( acc_idx<acc_cnt );
      test_acc_t const * a = &acc[ acc_idx ];
      FD_TEST( !memcmp( res->account_header.pubkey, a->key.uc, sizeof(fd_pubkey_t) ) );
      FD_TEST( res->account_header.lamports  ==a->lamports   );
      FD_TEST( res->account_header.data_len  ==a->data_len   );
      FD_TEST( res->account_header.executable==a->executable );
      FD_TEST( res->account_header.rent_epoch==ULONG_MAX     );
      FD_TEST( !memcmp( res->account_header.owner, a->owner.uc, sizeof(fd_pubkey_t) ) );
      FD_TEST( res->account_header.slot==slot );
      data_off = 0UL;
      if( FD_UNLIKELY( !a->data_len ) ) acc_idx++;
      break;
    }
    case FD_SSPARSE_ADVANCE_ACCOUNT_DATA: {
      test_acc_t const * a = &acc[ acc_idx ];
      FD_TEST( data_off+res->account_data.data_sz<=a->data_len );
      FD_TEST( !memcmp( res->account_data.data, a->data+data_off, res->account_data.data_sz ) );
      data_off += res->account_data.data_sz;
      if( FD_LIKELY( data_off==a->data_len ) ) acc_idx++;
      break;
    }
    case FD_SSPARSE_ADVANCE_APPENDVEC_DONE:
      FD_TEST( res->appendvec.slot==slot );
      FD_TEST( res->appendvec.id==0UL   );
      in_vec   = 0;
      vec_done = 1;
      break;
    default:
      break;
    }
  }

  FD_TEST( vec_done );
  FD_TEST( acc_idx==acc_cnt );
  free( raw );
}

/* A stream carries accounts of every shape: one that does not exist,
   one with no data, a small one, and the largest the runtime allows. */

FD_UNIT_TEST( appendvec_roundtrip ) {
  env_create();
  write_fixed();

  static uchar big[ FD_RUNTIME_ACC_SZ_MAX ];
  for( ulong i=0UL; i<sizeof(big); i++ ) big[ i ] = (uchar)fd_ulong_hash( i );
  static uchar small[ 37 ];
  for( ulong i=0UL; i<sizeof(small); i++ ) small[ i ] = (uchar)( i+1UL );

  test_acc_t acc[ 4 ] = {
    { .key = {{ 1 }}, .lamports = 0UL,        .executable = 0, .owner = {{ 0 }},
      .data_len = 0UL,            .data = NULL  },
    { .key = {{ 2 }}, .lamports = 1UL,        .executable = 0, .owner = {{ 7 }},
      .data_len = 0UL,            .data = NULL  },
    { .key = {{ 3 }}, .lamports = 12345UL,    .executable = 1, .owner = {{ 8 }},
      .data_len = sizeof(small),  .data = small },
    { .key = {{ 4 }}, .lamports = ULONG_MAX,  .executable = 0, .owner = {{ 9 }},
      .data_len = sizeof(big),    .data = big   }
  };

  for( ulong i=0UL; i<4UL; i++ ) {
    stream->raw_sz += strmk_encode_account( stream->raw + sizeof(fd_tar_meta_t) + stream->raw_sz,
                                            TEST_SLOT_X, &acc[ i ].key, acc[ i ].lamports,
                                            acc[ i ].executable, acc[ i ].owner.uc,
                                            acc[ i ].data, acc[ i ].data_len );
  }
  /* the record of an account that does not exist is a header only */
  FD_TEST( stream->raw_sz==4UL*sizeof(snap_acc_hdr_t)
                          + fd_ulong_align_up( sizeof(small), 8UL )
                          + sizeof(big) );
  strmk_appendvec_flush( ctx, stream, TEST_SLOT, 0UL );
  FD_TEST( !stream->raw_sz );

  expect_accounts( TEST_SLOT, acc, 4UL );
  env_destroy();
}

/* A block that touched nothing new still gets an appendvec, holding
   the one record the tile falls back to. */

FD_UNIT_TEST( appendvec_filler ) {
  env_create();
  write_fixed();

  test_acc_t acc[ 1 ] = {
    { .key = {{ 0 }}, .lamports = 0UL, .executable = 0, .owner = {{ 0 }}, .data_len = 0UL, .data = NULL }
  };
  acc[ 0 ].key   = fd_sysvar_instructions_id;
  acc[ 0 ].owner = fd_solana_system_program_id;

  stream->raw_sz = strmk_encode_account( stream->raw + sizeof(fd_tar_meta_t), TEST_SLOT_X,
                                         &fd_sysvar_instructions_id, 0UL, 0,
                                         fd_solana_system_program_id.uc, NULL, 0UL );
  strmk_appendvec_flush( ctx, stream, TEST_SLOT, 0UL );

  expect_accounts( TEST_SLOT, acc, 1UL );
  env_destroy();
}

/* The sent set holds every key a stream carried, up to the share of
   its entries the tile allows. */

FD_UNIT_TEST( sent_set ) {
#define SENT_MAX (1024UL)
  static strmk_sent_t  sent[ SENT_MAX ];
  static strmk_stream_t s[1];
  memset( sent, 0, sizeof(sent) );
  memset( s,    0, sizeof(s)    );
  s->sent = sent;

  ulong cap = ( SENT_MAX*STRMK_SENT_LOAD_NUM )/STRMK_SENT_LOAD_DEN;
  for( ulong i=0UL; i<cap; i++ ) {
    fd_pubkey_t key = {{ 0 }};
    FD_STORE( ulong, key.uc,      fd_ulong_hash( i      ) );
    FD_STORE( ulong, key.uc+8UL,  fd_ulong_hash( i+1UL  ) );
    FD_STORE( ulong, key.uc+16UL, fd_ulong_hash( i+2UL  ) );
    FD_STORE( ulong, key.uc+24UL, fd_ulong_hash( i+3UL  ) );
    FD_TEST( !strmk_sent_test( s, SENT_MAX, &key ) );
    strmk_sent_insert( s, SENT_MAX, &key, TEST_SLOT+i );
    /* inserting a key the stream already carried changes nothing */
    strmk_sent_insert( s, SENT_MAX, &key, TEST_SLOT+i+1UL );
    FD_TEST( strmk_sent_test( s, SENT_MAX, &key ) );
  }
  FD_TEST( s->sent_cnt==cap );

  /* every key is still found once the set is as full as it gets */
  for( ulong i=0UL; i<cap; i++ ) {
    fd_pubkey_t key = {{ 0 }};
    FD_STORE( ulong, key.uc,      fd_ulong_hash( i      ) );
    FD_STORE( ulong, key.uc+8UL,  fd_ulong_hash( i+1UL  ) );
    FD_STORE( ulong, key.uc+16UL, fd_ulong_hash( i+2UL  ) );
    FD_STORE( ulong, key.uc+24UL, fd_ulong_hash( i+3UL  ) );
    FD_TEST( strmk_sent_test( s, SENT_MAX, &key ) );
    FD_TEST( strmk_sent_query( sent, SENT_MAX, &key )->slot==TEST_SLOT+i );
  }

  /* a key the stream never carried is not in the set */
  for( ulong i=cap; i<cap+64UL; i++ ) {
    fd_pubkey_t key = {{ 0 }};
    FD_STORE( ulong, key.uc,      fd_ulong_hash( i      ) );
    FD_STORE( ulong, key.uc+8UL,  fd_ulong_hash( i+1UL  ) );
    FD_STORE( ulong, key.uc+16UL, fd_ulong_hash( i+2UL  ) );
    FD_STORE( ulong, key.uc+24UL, fd_ulong_hash( i+3UL  ) );
    FD_TEST( !strmk_sent_test( s, SENT_MAX, &key ) );
  }
#undef SENT_MAX
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_unit_tests( argc, argv );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
