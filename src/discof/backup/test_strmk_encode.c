/* Round trips the boot stream archive writer through fd_ssparse, which
   is what a booting peer parses it with, and exercises the sent set a
   stream dedups its accounts with. */

#define _GNU_SOURCE
#define FD_TILE_TEST
#pragma GCC diagnostic ignored "-Wunused-function"

#include "../../flamenco/accdb/fd_accdb.h"

/* The tile reads accounts through the accounts database, which this
   test stands in for: every account exists, its data is its own
   address followed by the fork it was read at, so the parse can tell
   which fork a block was written from. */

static int
mock_accdb_read_one_nocache( fd_accdb_t *       accdb,
                             fd_accdb_fork_id_t fork_id,
                             uchar const *      pubkey,
                             ulong *            out_lamports,
                             int *              out_executable,
                             uchar *            out_owner,
                             uchar *            out_data,
                             ulong *            out_data_len );

#define fd_accdb_read_one_nocache mock_accdb_read_one_nocache
#include "fd_strmk_tile.c"
#undef fd_accdb_read_one_nocache

static int
mock_accdb_read_one_nocache( fd_accdb_t *       accdb,
                             fd_accdb_fork_id_t fork_id,
                             uchar const *      pubkey,
                             ulong *            out_lamports,
                             int *              out_executable,
                             uchar *            out_owner,
                             uchar *            out_data,
                             ulong *            out_data_len ) {
  (void)accdb;
  *out_lamports   = 1000UL + (ulong)fork_id.val;
  *out_executable = 0;
  memcpy( out_owner, fd_solana_system_program_id.uc, sizeof(fd_pubkey_t) );
  memcpy( out_data, pubkey, sizeof(fd_pubkey_t) );
  FD_STORE( ushort, out_data+sizeof(fd_pubkey_t), fork_id.val );
  *out_data_len = sizeof(fd_pubkey_t)+sizeof(ushort);
  return FD_ACCDB_READ_ONE_NOCACHE_CACHE;
}

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

static fd_strmk_t       ctx[1];
static strmk_stream_t * stream; /* the one stream of the test tile */

/* env_create hands the archive writer a file to write into and the
   buffers it compresses through. */

static void
env_create( void ) {
  memset( ctx, 0, sizeof(fd_strmk_t) );
  ctx->stream_max = 1U;
  stream          = &ctx->stream[ 0 ];

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

/* backlog_env gives the tile a block pool and one open stream at
   TEST_SLOT_X, with the fixed part of an archive already written. */

#define BACKLOG_KEY_MAX (1024UL)

static strmk_sent_t * backlog_sent;
static void *         backlog_keys;

static void
backlog_env( void ) {
  env_create();
  write_fixed();

  backlog_keys = mmap( NULL, STRMK_BLOCK_MAX*sizeof(strmk_keyset_t), PROT_READ|PROT_WRITE,
                       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( backlog_keys!=MAP_FAILED );
  for( ulong i=0UL; i<STRMK_BLOCK_MAX; i++ ) {
    ctx->block[ i ].state = STRMK_BLOCK_FREE;
    ctx->block[ i ].keys  = (strmk_keyset_t *)backlog_keys + i;
  }
  ctx->retain_head = 0UL;
  ctx->retain_tail = 0UL;

  backlog_sent = aligned_alloc( alignof(strmk_sent_t), BACKLOG_KEY_MAX*sizeof(strmk_sent_t) );
  FD_TEST( backlog_sent );
  memset( backlog_sent, 0, BACKLOG_KEY_MAX*sizeof(strmk_sent_t) );

  ctx->key_max    = BACKLOG_KEY_MAX;
  ctx->key_cap    = ( BACKLOG_KEY_MAX*STRMK_SENT_LOAD_NUM )/STRMK_SENT_LOAD_DEN;
  ctx->acc_data   = malloc( FD_RUNTIME_ACC_SZ_MAX );
  FD_TEST( ctx->acc_data );

  stream->open       = 1;
  stream->first_slot = ULONG_MAX;
  stream->sent       = backlog_sent;
}

static void
backlog_env_destroy( void ) {
  free( ctx->acc_data );
  free( backlog_sent );
  FD_TEST( !munmap( backlog_keys, STRMK_BLOCK_MAX*sizeof(strmk_keyset_t) ) );
  env_destroy();
}

/* backlog_retain adds one completed block to the ones the tile kept. */

static strmk_block_t *
backlog_retain( ulong slot,
                ulong bank_idx,
                ulong parent_bank_idx,
                ulong parent_slot ) {
  strmk_block_t * block = strmk_block_alloc( ctx );
  FD_TEST( block );
  block->slot            = slot;
  block->parent_slot     = parent_slot;
  block->bank_idx        = bank_idx;
  block->bank_seq        = slot;
  block->parent_bank_idx = parent_bank_idx;
  block->parent_fork     = (fd_accdb_fork_id_t){ (ushort)slot };

  fd_pubkey_t key = {{ 0 }};
  FD_STORE( ulong, key.uc, slot );
  FD_TEST( strmk_block_key_add( block, &key ) );
  /* a key every block touches, so the sent set has to dedup it */
  fd_pubkey_t shared = {{ 7 }};
  FD_TEST( strmk_block_key_add( block, &shared ) );

  strmk_block_retain( ctx, block );
  return block;
}

/* appendvec_slots parses the archive and returns the slots of its
   appendvecs in the order they were written. */

static ulong
appendvec_slots( ulong * out_slot,
                 ulong   out_max ) {
  ulong   raw_sz;
  uchar * raw = read_back( &raw_sz );

  fd_ssparse_t ssparse[1];
  FD_TEST( fd_ssparse_init( ssparse ) );
  fd_ssparse_batch_enable( ssparse, 0 );

  ulong off = 0UL;
  ulong cnt = 0UL;
  for(;;) {
    fd_ssparse_advance_result_t res[1];
    int adv = fd_ssparse_advance( ssparse, raw+off, raw_sz-off, res );
    FD_TEST( adv!=FD_SSPARSE_ADVANCE_ERROR );
    off += res->bytes_consumed;
    if( FD_UNLIKELY( adv==FD_SSPARSE_ADVANCE_AGAIN && off>=raw_sz ) ) break;
    if( FD_LIKELY( adv==FD_SSPARSE_ADVANCE_APPENDVEC ) ) {
      FD_TEST( cnt<out_max );
      out_slot[ cnt++ ] = res->appendvec.slot;
      fd_ssparse_appendvec_parse( ssparse );
    }
    /* every account was read at the fork of the block it belongs to */
    if( FD_UNLIKELY( adv==FD_SSPARSE_ADVANCE_ACCOUNT_HEADER && cnt>1UL ) ) {
      FD_TEST( res->account_header.lamports==1000UL+out_slot[ cnt-1UL ] );
    }
  }
  free( raw );
  return cnt;
}

/* A stream opens below blocks that already ran, so those blocks are
   written into it before the blocks it then carries live. */

FD_UNIT_TEST( backlog_order ) {
  backlog_env();

  /* slots 101, 102 and 103 ran after 100 and chain back to its bank */
  backlog_retain( 101UL, 11UL, 10UL, TEST_SLOT_X );
  backlog_retain( 102UL, 12UL, 11UL, 101UL      );
  backlog_retain( 103UL, 13UL, 12UL, 102UL      );
  /* and one that ran before the stream's slot, which it does not want */
  backlog_retain(  99UL,  9UL,  8UL,  98UL      );

  FD_TEST( strmk_backlog_link( ctx, TEST_SLOT_X, 10UL ) );

  /* the bundle of the stream's own slot comes first */
  fd_pubkey_t bundle = {{ 3 }};
  fd_pubkey_t ignore;
  strmk_write_key( ctx, stream, (fd_accdb_fork_id_t){ (ushort)TEST_SLOT_X },
                   &bundle, TEST_SLOT_X, &ignore );
  strmk_appendvec_flush( ctx, stream, TEST_SLOT_X, 0UL );

  strmk_backlog_write( ctx, NULL, stream );

  /* then one block the stream carries live */
  strmk_block_t * live = strmk_block_alloc( ctx );
  FD_TEST( live );
  live->slot        = 104UL;
  live->parent_slot = 103UL;
  live->parent_fork = (fd_accdb_fork_id_t){ 104 };
  fd_pubkey_t key = {{ 0 }};
  FD_STORE( ulong, key.uc, 104UL );
  FD_TEST( strmk_block_key_add( live, &key ) );
  strmk_block_read ( ctx, stream, live );
  strmk_block_flush( ctx, NULL, stream, live );

  ulong slot[ 16 ];
  ulong cnt = appendvec_slots( slot, 16UL );
  FD_TEST( cnt==5UL );
  FD_TEST( slot[ 0 ]==TEST_SLOT_X );
  FD_TEST( slot[ 1 ]==101UL );
  FD_TEST( slot[ 2 ]==102UL );
  FD_TEST( slot[ 3 ]==103UL );
  FD_TEST( slot[ 4 ]==104UL );

  /* the key every block touches was carried once, by the first of them */
  fd_pubkey_t shared = {{ 7 }};
  FD_TEST( strmk_sent_query( stream->sent, BACKLOG_KEY_MAX, &shared )->slot==101UL );
  /* the first block the stream carried is the oldest it had to catch
     up on, so the live blocks that follow are not checked for a gap */
  FD_TEST( stream->first_slot==101UL );

  backlog_env_destroy();
}

/* A stream is refused when the blocks the tile kept do not cover
   everything that ran after its slot. */

FD_UNIT_TEST( backlog_refused ) {
  backlog_env();

  /* the block that ran right after slot 100 is no longer kept */
  backlog_retain( 102UL, 12UL, 11UL, 101UL );
  backlog_retain( 103UL, 13UL, 12UL, 102UL );
  FD_TEST( !strmk_backlog_link( ctx, TEST_SLOT_X, 10UL ) );

  /* a block in the middle of the chain is missing */
  strmk_blocks_drop( ctx );
  backlog_retain( 101UL, 11UL, 10UL, TEST_SLOT_X );
  backlog_retain( 103UL, 13UL, 12UL, 102UL       );
  FD_TEST( !strmk_backlog_link( ctx, TEST_SLOT_X, 10UL ) );

  /* nothing ran after the stream's slot yet, which is not a gap */
  strmk_blocks_drop( ctx );
  backlog_retain( 99UL, 9UL, 8UL, 98UL );
  FD_TEST( strmk_backlog_link( ctx, TEST_SLOT_X, 10UL ) );

  /* a refused stream writes nothing */
  strmk_blocks_drop( ctx );
  backlog_retain( 103UL, 13UL, 12UL, 102UL );
  ulong file_sz = stream->file_sz;
  FD_TEST( !strmk_backlog_link( ctx, TEST_SLOT_X, 10UL ) );
  FD_TEST( stream->file_sz==file_sz );

  backlog_env_destroy();
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
