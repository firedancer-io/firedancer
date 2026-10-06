/* Round trips the boot stream archive writer through fd_ssparse, which
   is what a booting peer parses it with, and exercises the sent set a
   stream dedups its accounts with. */

#define _GNU_SOURCE
#define FD_TILE_TEST
#pragma GCC diagnostic ignored "-Wunused-function"

#include "../../flamenco/accdb/fd_accdb.h"
#include "../../flamenco/runtime/fd_bank.h"

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

/* The tile looks a block's parent bank up to check that the fork it
   names is still live; the test keeps a flat table of banks by
   index. */

#define TEST_BANK_MAX (64UL)

static fd_bank_t * mock_bank[ TEST_BANK_MAX ];
static ulong       mock_bank_queries;

static fd_bank_t *
mock_banks_bank_query( fd_banks_t * banks,
                       ulong        bank_idx ) {
  (void)banks;
  mock_bank_queries++;
  if( FD_UNLIKELY( bank_idx>=TEST_BANK_MAX ) ) return NULL;
  return mock_bank[ bank_idx ];
}

#define fd_accdb_read_one_nocache mock_accdb_read_one_nocache
#define fd_banks_bank_query       mock_banks_bank_query
#include "fd_strmk_tile.c"
#undef fd_banks_bank_query
#undef fd_accdb_read_one_nocache

/* The tile resolves a sent set entry once per key and reads what it
   needs off it.  These ask the same two questions of one key, and
   insert through a freshly resolved entry. */

static int
sent_test( strmk_stream_t const * stream,
           ulong                  slot_cnt,
           fd_pubkey_t const *    key ) {
  strmk_sent_t const * ele = strmk_sent_query( stream->sent, slot_cnt, key );
  return ele && !!ele->slot;
}

static int
sent_table( strmk_stream_t const * stream,
            ulong                  slot_cnt,
            fd_pubkey_t const *    key ) {
  strmk_sent_t const * ele = strmk_sent_query( stream->sent, slot_cnt, key );
  return ele && !!( ele->slot & STRMK_SENT_TABLE );
}

static int
sent_insert( strmk_stream_t *    stream,
             ulong               slot_cnt,
             fd_pubkey_t const * key,
             ulong               slot,
             int                 table ) {
  return strmk_sent_insert( stream, strmk_sent_query( stream->sent, slot_cnt, key ), key, slot, table );
}

/* mock_bank_add makes a bank at bank_idx that is alive and frozen. */

static void
mock_bank_add( ulong bank_idx ) {
  FD_TEST( bank_idx<TEST_BANK_MAX );
  if( FD_UNLIKELY( mock_bank[ bank_idx ] ) ) return;
  mock_bank[ bank_idx ] = aligned_alloc( 128UL, fd_ulong_align_up( sizeof(fd_bank_t), 128UL ) );
  FD_TEST( mock_bank[ bank_idx ] );
  memset( mock_bank[ bank_idx ], 0, sizeof(fd_bank_t) );
  mock_bank[ bank_idx ]->idx      = bank_idx;
  mock_bank[ bank_idx ]->bank_seq = bank_idx;
  mock_bank[ bank_idx ]->state    = FD_BANK_STATE_FROZEN;
}

static void
mock_bank_clear( void ) {
  for( ulong i=0UL; i<TEST_BANK_MAX; i++ ) {
    free( mock_bank[ i ] );
    mock_bank[ i ] = NULL;
  }
}

/* One account a test shapes, to drive the owners the tile follows. */

static fd_pubkey_t mock_shaped_key;
static fd_pubkey_t mock_shaped_owner;
static uchar       mock_shaped_data[ 4096 ];
static ulong       mock_shaped_len;
static ushort      mock_shaped_fork; /* the fork it was created at */
static int         mock_shaped;

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
  if( FD_UNLIKELY( mock_shaped && !memcmp( pubkey, mock_shaped_key.uc, sizeof(fd_pubkey_t) ) ) ) {
    if( FD_UNLIKELY( fork_id.val<mock_shaped_fork ) ) {
      *out_lamports = 0UL;
      return FD_ACCDB_READ_ONE_NOCACHE_MISS;
    }
    *out_lamports   = 1000UL + (ulong)fork_id.val;
    *out_executable = 0;
    memcpy( out_owner, mock_shaped_owner.uc, sizeof(fd_pubkey_t) );
    memcpy( out_data,  mock_shaped_data,     mock_shaped_len     );
    *out_data_len = mock_shaped_len;
    return FD_ACCDB_READ_ONE_NOCACHE_CACHE;
  }
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
static strmk_stream_t * stream;  /* the one stream of the test tile */
static void *           zst_mem; /* its static compressor */

/* A stem the tile can publish its two out links through, so the paths
   that give a bank back or withdraw a file can be driven. */

#define TEST_STEM_DEPTH (128UL)

static fd_stem_context_t test_stem[1];
static fd_frag_meta_t *  test_mcache[ 2 ];
static ulong             test_seq[ 2 ];
static ulong             test_depth[ 2 ];
static int               test_reliable[ 2 ];
static ulong             test_cr_avail[ 2 ];
static ulong             test_min_cr_avail;

static void
test_stem_create( void ) {
  for( ulong i=0UL; i<2UL; i++ ) {
    void * mem = aligned_alloc( fd_mcache_align(), fd_mcache_footprint( TEST_STEM_DEPTH, 0UL ) );
    FD_TEST( mem );
    test_mcache  [ i ] = fd_mcache_join( fd_mcache_new( mem, TEST_STEM_DEPTH, 0UL, 0UL ) );
    FD_TEST( test_mcache[ i ] );
    test_seq     [ i ] = 0UL;
    test_depth   [ i ] = TEST_STEM_DEPTH;
    test_reliable[ i ] = 0;
    test_cr_avail[ i ] = TEST_STEM_DEPTH;
  }
  test_min_cr_avail = TEST_STEM_DEPTH;
  *test_stem = (fd_stem_context_t) {
    .mcaches             = test_mcache,
    .seqs                = test_seq,
    .depths              = test_depth,
    .out_reliable        = test_reliable,
    .cr_avail            = test_cr_avail,
    .min_cr_avail        = &test_min_cr_avail,
    .cr_decrement_amount = 1UL
  };
}

static void
test_stem_destroy( void ) {
  for( ulong i=0UL; i<2UL; i++ ) free( fd_mcache_delete( fd_mcache_leave( test_mcache[ i ] ) ) );
}

/* env_create hands the archive writer a file to write into and the
   buffers it compresses through. */

/* The index of the blocks in flight, one entry per bank the test
   hands out. */

static uint test_bank_block[ TEST_BANK_MAX ];

static void
env_create( void ) {
  memset( ctx, 0, sizeof(fd_strmk_t) );
  ctx->stream_max = 1U;
  stream          = &ctx->stream[ 0 ];

  memset( test_bank_block, 0xff, sizeof(test_bank_block) );
  ctx->bank_block = test_bank_block;
  ctx->bank_max   = TEST_BANK_MAX;

  ctx->comp = aligned_alloc( 16UL, STRMK_COMP_BUF_SZ );
  FD_TEST( ctx->comp );

  stream->raw = mmap( NULL, STRMK_RAW_BUF_SZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( stream->raw!=MAP_FAILED );

  ulong zst_sz = ZSTD_estimateCStreamSize( FD_BACKUP_ZSTD_LEVEL );
  zst_mem = aligned_alloc( 64UL, fd_ulong_align_up( zst_sz, 64UL ) );
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
  FD_TEST( !munmap( stream->raw, STRMK_RAW_BUF_SZ ) );
  free( zst_mem   );
  free( ctx->comp );
}

/* write_entry writes one tar entry of content_sz bytes the caller has
   already staged behind the tar header. */

static void
write_entry( char const * name,
             ulong        content_sz ) {
  fd_backup_tar_named_hdr( (fd_tar_meta_t *)stream->raw, name, content_sz );
  zip_entry( ctx, stream, content_sz );
}

/* write_fixed writes the entries a peer needs before any appendvec:
   the tile's own version and directory headers, then a manifest and a
   status cache whose content does not matter here, only that the
   parser accepts the archive up to the accounts. */

#define TEST_MANIFEST_SZ (777UL)
#define TEST_STATUS_SZ   (333UL)

static void
write_fixed( void ) {
  strmk_open_entries( ctx, stream );

  char name[ FD_TAR_NAME_SZ ];
  FD_TEST( fd_cstr_printf_check( name, sizeof(name), NULL, "snapshots/%lu/%lu", TEST_SLOT_X, TEST_SLOT_X ) );
  memset( stream->raw + sizeof(fd_tar_meta_t), 0xa5, TEST_MANIFEST_SZ );
  write_entry( name, TEST_MANIFEST_SZ );

  memset( stream->raw + sizeof(fd_tar_meta_t), 0x5a, TEST_STATUS_SZ );
  write_entry( "snapshots/status_cache", TEST_STATUS_SZ );
}

/* TEST_RAW_MAX bounds the uncompressed archive a test produces. */

#define TEST_RAW_MAX (512UL<<20)

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

  uchar * raw = mmap( NULL, TEST_RAW_MAX, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( raw!=MAP_FAILED );
  ZSTD_DStream * dst = ZSTD_createDStream();
  FD_TEST( dst );
  ZSTD_inBuffer  in  = { .src = comp, .size = comp_max, .pos = 0UL };
  ZSTD_outBuffer out = { .dst = raw,  .size = TEST_RAW_MAX, .pos = 0UL };
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
  /* the stream parser is told where each appendvec ends */
  fd_ssparse_appendvec_done_enable( ssparse, 1 );

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
  FD_TEST( !munmap( raw, TEST_RAW_MAX ) );
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

/* An archive the tile wrote parses as a whole: the version file it
   writes, the manifest and status cache it streams in, the appendvecs,
   and the end of archive marker a clean close leaves. */

FD_UNIT_TEST( archive_roundtrip ) {
  env_create();
  write_fixed();

  test_acc_t acc[ 1 ] = {
    { .key = {{ 5 }}, .lamports = 7UL, .executable = 0, .owner = {{ 6 }}, .data_len = 0UL, .data = NULL }
  };
  stream->raw_sz = strmk_encode_account( stream->raw + sizeof(fd_tar_meta_t), TEST_SLOT_X,
                                         &acc[ 0 ].key, acc[ 0 ].lamports, acc[ 0 ].executable,
                                         acc[ 0 ].owner.uc, NULL, 0UL );
  strmk_appendvec_flush( ctx, stream, TEST_SLOT, 0UL );

  /* the two zero blocks a clean close ends the archive with */
  memset( stream->raw, 0, 2UL*sizeof(fd_tar_meta_t) );
  zip_push( ctx, stream, stream->raw, 2UL*sizeof(fd_tar_meta_t), ZSTD_e_end );

  ulong   raw_sz;
  uchar * raw = read_back( &raw_sz );

  fd_ssparse_t ssparse[1];
  FD_TEST( fd_ssparse_init( ssparse ) );
  fd_ssparse_batch_enable( ssparse, 0 );
  /* the stream parser is told where each appendvec ends */
  fd_ssparse_appendvec_done_enable( ssparse, 1 );

  ulong off          = 0UL;
  ulong manifest_sz  = 0UL;
  ulong status_sz    = 0UL;
  int   done         = 0;
  for(;;) {
    fd_ssparse_advance_result_t res[1];
    int adv = fd_ssparse_advance( ssparse, raw+off, raw_sz-off, res );
    FD_TEST( adv!=FD_SSPARSE_ADVANCE_ERROR );
    off += res->bytes_consumed;
    if( FD_UNLIKELY( adv==FD_SSPARSE_ADVANCE_DONE ) ) { done = 1; break; }
    if( FD_UNLIKELY( adv==FD_SSPARSE_ADVANCE_AGAIN && off>=raw_sz ) ) break;
    switch( adv ) {
    case FD_SSPARSE_ADVANCE_MANIFEST:
    case FD_SSPARSE_ADVANCE_MANIFEST_DONE:
      manifest_sz += res->manifest.data_sz;
      break;
    case FD_SSPARSE_ADVANCE_STATUS_CACHE:
      status_sz += res->status_cache.data_sz;
      break;
    case FD_SSPARSE_ADVANCE_APPENDVEC:
      FD_TEST( res->appendvec.slot==TEST_SLOT );
      fd_ssparse_appendvec_parse( ssparse );
      break;
    default:
      break;
    }
  }

  /* the parser read the version file, both headers and the marker */
  FD_TEST( done );
  FD_TEST( manifest_sz==TEST_MANIFEST_SZ );
  FD_TEST( status_sz  ==TEST_STATUS_SZ   );
  FD_TEST( !munmap( raw, TEST_RAW_MAX ) );
  env_destroy();
}

/* An appendvec that does not fit the stage spills into overflow files,
   which come before the file a peer treats as the end of the slot. */

FD_UNIT_TEST( appendvec_overflow ) {
  env_create();
  write_fixed();

  /* enough 10 MiB accounts that the 64 MiB stage has to spill twice */
  static uchar big[ FD_RUNTIME_ACC_SZ_MAX ];
  memset( big, 0x33, sizeof(big) );
  ulong rec_sz = sizeof(snap_acc_hdr_t) + sizeof(big);
  ulong cnt    = 2UL*( STRMK_RAW_BUF_SZ/rec_sz ) + 1UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_pubkey_t key = {{ 0 }};
    FD_STORE( ulong, key.uc, i );
    if( FD_UNLIKELY( sizeof(fd_tar_meta_t)+stream->raw_sz+rec_sz>STRMK_RAW_BUF_SZ ) ) {
      strmk_appendvec_flush( ctx, stream, TEST_SLOT, ++stream->vec_id );
    }
    stream->raw_sz += strmk_encode_account( stream->raw + sizeof(fd_tar_meta_t) + stream->raw_sz,
                                            TEST_SLOT_X, &key, 1UL, 0, big, big, sizeof(big) );
  }
  FD_TEST( stream->vec_id>=2UL );
  strmk_appendvec_flush( ctx, stream, TEST_SLOT, 0UL );

  ulong   raw_sz;
  uchar * raw = read_back( &raw_sz );
  fd_ssparse_t ssparse[1];
  FD_TEST( fd_ssparse_init( ssparse ) );
  fd_ssparse_batch_enable( ssparse, 0 );
  /* the stream parser is told where each appendvec ends */
  fd_ssparse_appendvec_done_enable( ssparse, 1 );

  ulong off = 0UL;
  ulong id[ 8 ];
  ulong id_cnt = 0UL;
  for(;;) {
    fd_ssparse_advance_result_t res[1];
    int adv = fd_ssparse_advance( ssparse, raw+off, raw_sz-off, res );
    FD_TEST( adv!=FD_SSPARSE_ADVANCE_ERROR );
    off += res->bytes_consumed;
    if( FD_UNLIKELY( adv==FD_SSPARSE_ADVANCE_AGAIN && off>=raw_sz ) ) break;
    if( FD_LIKELY( adv==FD_SSPARSE_ADVANCE_APPENDVEC ) ) {
      FD_TEST( res->appendvec.slot==TEST_SLOT );
      FD_TEST( id_cnt<8UL );
      id[ id_cnt++ ] = res->appendvec.id;
      fd_ssparse_appendvec_parse( ssparse );
    }
  }

  /* the overflow files are numbered from one and the last file is zero */
  FD_TEST( id_cnt==stream->vec_id+1UL );
  for( ulong i=0UL; i+1UL<id_cnt; i++ ) FD_TEST( id[ i ]==i+1UL );
  FD_TEST( id[ id_cnt-1UL ]==0UL );

  FD_TEST( !munmap( raw, TEST_RAW_MAX ) );
  env_destroy();
}

/* backlog_env gives the tile a block pool and one open stream at
   TEST_SLOT_X, with the fixed part of an archive already written. */

#define BACKLOG_KEY_MAX (1024UL)

static strmk_sent_t * backlog_sent;
static void *         backlog_keys;

static void
backlog_env( ulong key_max ) {
  env_create();
  write_fixed();

  backlog_keys = mmap( NULL, STRMK_BLOCK_MAX*sizeof(strmk_keyset_t), PROT_READ|PROT_WRITE,
                       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( backlog_keys!=MAP_FAILED );
  for( ulong i=0UL; i<STRMK_BLOCK_MAX; i++ ) ctx->block[ i ].keys = (strmk_keyset_t *)backlog_keys + i;
  ctx->retain_head = 0UL;
  ctx->retain_tail = 0UL;
  mock_bank_clear();
  test_stem_create();
  ctx->replay_out_idx = 0UL;
  ctx->out.out_idx    = 1UL;
  ctx->out.mem        = NULL;

  backlog_sent = aligned_alloc( alignof(strmk_sent_t), key_max*sizeof(strmk_sent_t) );
  FD_TEST( backlog_sent );
  memset( backlog_sent, 0, key_max*sizeof(strmk_sent_t) );

  ctx->key_max    = key_max;
  ctx->key_cap    = ( key_max*STRMK_SENT_LOAD_NUM )/STRMK_SENT_LOAD_DEN;
  ctx->acc_data   = malloc( FD_RUNTIME_ACC_SZ_MAX );
  FD_TEST( ctx->acc_data );

  /* One open stream that starts at TEST_SLOT_X, whose bank is 10.  It
     was never published, so closing it tells the file server
     nothing. */
  stream->open      = 1;
  stream->published = 0;
  stream->slot_x    = TEST_SLOT_X;
  stream->bank_idx  = 10UL;
  stream->bank_seq  = 10UL;
  stream->sent      = backlog_sent;
  memset( stream->carried, 0xff, sizeof(stream->carried) );
  mock_bank_add( 10UL );
}

static void
backlog_env_destroy( void ) {
  test_stem_destroy();
  mock_bank_clear();
  free( ctx->acc_data );
  free( backlog_sent );
  FD_TEST( !munmap( backlog_keys, STRMK_BLOCK_MAX*sizeof(strmk_keyset_t) ) );
  env_destroy();
}

/* backlog_retain adds one completed block to the ones the tile kept. */

static strmk_block_t *
backlog_retain( ulong slot,
                ulong bank_idx,
                ulong parent_bank_idx ) {
  strmk_block_t * block = strmk_block_alloc( ctx );
  FD_TEST( block );
  block->slot            = slot;
  block->bank_idx        = bank_idx;
  block->bank_seq        = bank_idx;
  block->parent_bank_idx = parent_bank_idx;
  block->parent_bank_seq = parent_bank_idx;
  block->parent_fork     = (fd_accdb_fork_id_t){ (ushort)slot };
  mock_bank_add( parent_bank_idx );

  fd_pubkey_t key = {{ 0 }};
  FD_STORE( ulong, key.uc, slot );
  FD_TEST( strmk_block_key_add( block, &key, 0 ) );
  /* a key every block touches, so the sent set has to dedup it */
  fd_pubkey_t shared = {{ 7 }};
  FD_TEST( strmk_block_key_add( block, &shared, 0 ) );

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
  /* the stream parser is told where each appendvec ends */
  fd_ssparse_appendvec_done_enable( ssparse, 1 );

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
  FD_TEST( !munmap( raw, TEST_RAW_MAX ) );
  return cnt;
}

/* A stream opens below blocks that already ran, so those blocks are
   written into it before the blocks it then carries live. */

FD_UNIT_TEST( backlog_order ) {
  backlog_env( BACKLOG_KEY_MAX );

  /* slots 101, 102 and 103 ran after 100 and chain back to its bank */
  backlog_retain( 101UL, 11UL, 10UL );
  backlog_retain( 102UL, 12UL, 11UL );
  backlog_retain( 103UL, 13UL, 12UL );
  /* and one that ran before the stream's slot, which it does not want */
  backlog_retain( 99UL, 9UL, 8UL );

  FD_TEST( strmk_backlog_link( ctx, TEST_SLOT_X, 10UL, 10UL ) );

  /* the bundle of the stream's own slot comes first */
  fd_pubkey_t bundle = {{ 3 }};
  strmk_write_account( ctx, 1U, (fd_accdb_fork_id_t){ (ushort)TEST_SLOT_X }, &bundle, TEST_SLOT_X, 0 );
  strmk_appendvec_flush( ctx, stream, TEST_SLOT_X, 0UL );

  FD_TEST( strmk_backlog_write( ctx, NULL, 0U ) );

  /* then one block the stream carries live */
  strmk_block_t * live = strmk_block_alloc( ctx );
  FD_TEST( live );
  live->slot            = 104UL;
  live->bank_idx        = 14UL;
  live->bank_seq        = 14UL;
  live->parent_bank_idx = 13UL;
  live->parent_bank_seq = 13UL;
  live->parent_fork     = (fd_accdb_fork_id_t){ 104 };
  fd_pubkey_t key = {{ 0 }};
  FD_STORE( ulong, key.uc, 104UL );
  FD_TEST( strmk_block_key_add( live, &key, 0 ) );
  FD_TEST( strmk_block_takers( ctx, live )==1U );
  strmk_block_read ( ctx, 1U, live );
  strmk_block_flush( ctx, NULL, 1U, 0, live );

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
  /* the stream remembers the blocks it carried, which is how the next
     one is recognised as chaining off it */
  FD_TEST( strmk_carried_test( stream, 13UL, 13UL ) );
  FD_TEST( !strmk_carried_test( stream, 13UL, 99UL ) );

  backlog_env_destroy();
}

/* A stream is refused when the blocks the tile kept do not cover
   everything that ran after its slot. */

FD_UNIT_TEST( backlog_refused ) {
  backlog_env( BACKLOG_KEY_MAX );

  /* the block that ran right after slot 100 is no longer kept */
  backlog_retain( 102UL, 12UL, 11UL );
  backlog_retain( 103UL, 13UL, 12UL );
  FD_TEST( !strmk_backlog_link( ctx, TEST_SLOT_X, 10UL, 10UL ) );

  /* a block in the middle of the chain is missing */
  strmk_blocks_drop( ctx );
  backlog_retain( 101UL, 11UL, 10UL );
  backlog_retain( 103UL, 13UL, 12UL );
  FD_TEST( !strmk_backlog_link( ctx, TEST_SLOT_X, 10UL, 10UL ) );

  /* nothing ran after the stream's slot yet, which is not a gap */
  strmk_blocks_drop( ctx );
  backlog_retain( 99UL, 9UL, 8UL );
  FD_TEST( strmk_backlog_link( ctx, TEST_SLOT_X, 10UL, 10UL ) );

  /* a chain that left the chain below the stream's slot is dropped,
     not refused, as long as the stream's own child is kept */
  strmk_blocks_drop( ctx );
  backlog_retain( 98UL, 8UL, 7UL );
  backlog_retain( 101UL, 11UL, 10UL );
  strmk_block_t * aside = backlog_retain( 102UL, 12UL, 8UL );
  FD_TEST( strmk_backlog_link( ctx, TEST_SLOT_X, 10UL, 10UL ) );
  FD_TEST( !aside->linked );

  /* nothing is kept but blocks have run past the stream's slot, which
     is what a reset leaves behind */
  strmk_blocks_drop( ctx );
  ctx->last_end_slot = 105UL;
  FD_TEST( !strmk_backlog_link( ctx, TEST_SLOT_X, 10UL, 10UL ) );
  ctx->last_end_slot = 0UL;

  /* a refused stream writes nothing */
  strmk_blocks_drop( ctx );
  backlog_retain( 103UL, 13UL, 12UL );
  ulong file_sz = stream->file_sz;
  FD_TEST( !strmk_backlog_link( ctx, TEST_SLOT_X, 10UL, 10UL ) );
  FD_TEST( stream->file_sz==file_sz );

  backlog_env_destroy();
}

/* Replay hands over the address of a lookup table it could not expand,
   and the stream carries the table and every address it names. */

FD_UNIT_TEST( lookup_table ) {
  backlog_env( BACKLOG_KEY_MAX );

  /* a table of three addresses behind its 56 byte header */
  fd_pubkey_t table = {{ 0x41 }};
  fd_pubkey_t addr[ 3 ] = { {{ 0x51 }}, {{ 0x52 }}, {{ 0x53 }} };
  mock_shaped_key   = table;
  mock_shaped_owner = fd_solana_address_lookup_table_program_id;
  mock_shaped_len   = FD_LOOKUP_TABLE_META_SIZE + sizeof(addr);
  mock_shaped_fork  = 0;
  FD_TEST( mock_shaped_len<=sizeof(mock_shaped_data) );
  memset( mock_shaped_data, 0, mock_shaped_len );
  memcpy( mock_shaped_data+FD_LOOKUP_TABLE_META_SIZE, addr, sizeof(addr) );
  mock_shaped = 1;

  strmk_block_t * block = strmk_block_alloc( ctx );
  FD_TEST( block );
  block->slot            = TEST_SLOT;
  block->parent_bank_idx = 10UL;
  block->parent_bank_seq = 10UL;
  block->parent_fork     = (fd_accdb_fork_id_t){ (ushort)TEST_SLOT };
  mock_bank_add( 10UL );
  FD_TEST( strmk_block_key_add( block, &table, 0 ) );

  strmk_block_read ( ctx, 1U, block );
  strmk_block_flush( ctx, NULL, 1U, 0, block );
  mock_shaped = 0;

  /* the table and all three of its addresses are in the appendvec */
  ulong   raw_sz;
  uchar * raw = read_back( &raw_sz );
  fd_ssparse_t ssparse[1];
  FD_TEST( fd_ssparse_init( ssparse ) );
  fd_ssparse_batch_enable( ssparse, 0 );
  /* the stream parser is told where each appendvec ends */
  fd_ssparse_appendvec_done_enable( ssparse, 1 );

  ulong off  = 0UL;
  int   seen = 0;
  for(;;) {
    fd_ssparse_advance_result_t res[1];
    int adv = fd_ssparse_advance( ssparse, raw+off, raw_sz-off, res );
    FD_TEST( adv!=FD_SSPARSE_ADVANCE_ERROR );
    off += res->bytes_consumed;
    if( FD_UNLIKELY( adv==FD_SSPARSE_ADVANCE_AGAIN && off>=raw_sz ) ) break;
    if( FD_LIKELY( adv==FD_SSPARSE_ADVANCE_APPENDVEC ) ) fd_ssparse_appendvec_parse( ssparse );
    if( FD_UNLIKELY( adv!=FD_SSPARSE_ADVANCE_ACCOUNT_HEADER ) ) continue;
    if( !memcmp( res->account_header.pubkey, table.uc, sizeof(fd_pubkey_t) ) ) seen |= 1;
    for( ulong i=0UL; i<3UL; i++ ) {
      if( !memcmp( res->account_header.pubkey, addr[ i ].uc, sizeof(fd_pubkey_t) ) ) seen |= 2<<i;
    }
  }
  FD_TEST( seen==0xf );

  FD_TEST( !munmap( raw, TEST_RAW_MAX ) );
  backlog_env_destroy();
}

/* open_cost reports what the fixed part of a stream costs to write.
   The sizes stand in for a mainnet stream: a manifest that is mostly
   account addresses, a status cache of 300 slot deltas, and a bundle
   of the vote accounts, feature gates and sysvars a peer needs. */

#define OPEN_MANIFEST_SZ (256UL<<20)
#define OPEN_STATUS_SZ   ( 32UL<<20)
#define OPEN_BUNDLE_CNT  (6500UL)
#define OPEN_BUNDLE_SZ   (3762UL) /* a vote account */

FD_UNIT_TEST( open_cost ) {
  backlog_env( 16384UL );

  /* A manifest is mostly account addresses, which do not compress,
     with a counter or a stake amount between every few of them. */
  uchar * fill = mmap( NULL, STRMK_RAW_BUF_SZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( fill!=MAP_FAILED );
  for( ulong i=0UL; i<STRMK_RAW_BUF_SZ; i+=sizeof(ulong) ) {
    ulong word = ( ( i/sizeof(ulong) )%10UL<8UL ) ? fd_ulong_hash( i ) : ( i&0xffffUL );
    FD_STORE( ulong, fill+i, word );
  }

  fd_tar_meta_t meta;
  long t0 = fd_log_wallclock();
  zip_push( ctx, stream, fd_backup_tar_named_hdr( &meta, "snapshots/1/1", OPEN_MANIFEST_SZ ),
            sizeof(fd_tar_meta_t), ZSTD_e_continue );
  for( ulong off=0UL; off<OPEN_MANIFEST_SZ; off+=STRMK_RAW_BUF_SZ ) {
    zip_push( ctx, stream, fill, fd_ulong_min( STRMK_RAW_BUF_SZ, OPEN_MANIFEST_SZ-off ), ZSTD_e_continue );
  }
  zip_pad( ctx, stream, OPEN_MANIFEST_SZ );
  long t1 = fd_log_wallclock();

  zip_push( ctx, stream, fd_backup_tar_named_hdr( &meta, FD_BACKUP_STATUS_CACHE_NAME, OPEN_STATUS_SZ ),
            sizeof(fd_tar_meta_t), ZSTD_e_continue );
  for( ulong off=0UL; off<OPEN_STATUS_SZ; off+=STRMK_RAW_BUF_SZ ) {
    zip_push( ctx, stream, fill, fd_ulong_min( STRMK_RAW_BUF_SZ, OPEN_STATUS_SZ-off ), ZSTD_e_continue );
  }
  zip_pad( ctx, stream, OPEN_STATUS_SZ );
  long t2 = fd_log_wallclock();

  mock_shaped_key   = (fd_pubkey_t){{ 0x61 }};
  mock_shaped_owner = fd_solana_system_program_id;
  mock_shaped_len   = 0UL;
  mock_shaped_fork  = 0;
  for( ulong i=0UL; i<OPEN_BUNDLE_CNT; i++ ) {
    fd_pubkey_t key = {{ 0 }};
    FD_STORE( ulong, key.uc, fd_ulong_hash( i ) );
    mock_shaped_key = key;
    mock_shaped_len = OPEN_BUNDLE_SZ;
    mock_shaped     = 1;
    memcpy( mock_shaped_data, fill+i, OPEN_BUNDLE_SZ );
    strmk_write_account( ctx, 1U, (fd_accdb_fork_id_t){ 1 }, &key, TEST_SLOT_X, 0 );
  }
  mock_shaped = 0;
  strmk_appendvec_flush( ctx, stream, TEST_SLOT_X, 0UL );
  long t3 = fd_log_wallclock();

  /* every account of the bundle landed in the stream */
  FD_TEST( !stream->sent_full );
  FD_TEST( stream->sent_cnt==OPEN_BUNDLE_CNT );

  ulong bundle_sz = OPEN_BUNDLE_CNT*( OPEN_BUNDLE_SZ+sizeof(snap_acc_hdr_t) );
  FD_LOG_NOTICE(( "stream open: manifest %lu MiB in %ld ms (%lu MiB/s), status cache %lu MiB in %ld ms (%lu MiB/s), "
                  "bundle %lu accounts %lu MiB in %ld ms (%lu MiB/s), %lu MiB in, %lu MiB written",
                  OPEN_MANIFEST_SZ>>20, ( t1-t0 )/(1000L*1000L), ( OPEN_MANIFEST_SZ>>20 )*1000UL/(ulong)fd_long_max( ( t1-t0 )/(1000L*1000L), 1L ),
                  OPEN_STATUS_SZ  >>20, ( t2-t1 )/(1000L*1000L), ( OPEN_STATUS_SZ  >>20 )*1000UL/(ulong)fd_long_max( ( t2-t1 )/(1000L*1000L), 1L ),
                  OPEN_BUNDLE_CNT, bundle_sz>>20, ( t3-t2 )/(1000L*1000L), ( bundle_sz>>20 )*1000UL/(ulong)fd_long_max( ( t3-t2 )/(1000L*1000L), 1L ),
                  ( OPEN_MANIFEST_SZ+OPEN_STATUS_SZ+bundle_sz )>>20, stream->file_sz>>20 ));

  FD_TEST( !munmap( fill, STRMK_RAW_BUF_SZ ) );
  backlog_env_destroy();
}

/* A block whose parent no stream carried is not any stream's block,
   and is skipped rather than breaking anything. */

FD_UNIT_TEST( ancestry_skip ) {
  backlog_env( BACKLOG_KEY_MAX );

  /* a child of the stream's slot is the stream's */
  strmk_block_t * child = strmk_block_alloc( ctx );
  FD_TEST( child );
  child->slot            = 101UL;
  child->bank_idx        = 11UL;
  child->bank_seq        = 11UL;
  child->parent_bank_idx = 10UL;
  child->parent_bank_seq = 10UL;
  child->parent_fork     = (fd_accdb_fork_id_t){ 101 };
  FD_TEST( strmk_block_takers( ctx, child )==1U );
  strmk_block_read ( ctx, 1U, child );
  strmk_block_flush( ctx, NULL, 1U, 0, child );

  /* a grandchild through it is too */
  strmk_block_t * grand = strmk_block_alloc( ctx );
  FD_TEST( grand );
  grand->slot            = 102UL;
  grand->bank_idx        = 12UL;
  grand->bank_seq        = 12UL;
  grand->parent_bank_idx = 11UL;
  grand->parent_bank_seq = 11UL;
  grand->parent_fork     = (fd_accdb_fork_id_t){ 102 };
  FD_TEST( strmk_block_takers( ctx, grand )==1U );

  /* one that chains off a bank the stream never carried is not */
  strmk_block_t * other = strmk_block_alloc( ctx );
  FD_TEST( other );
  other->slot            = 103UL;
  other->bank_idx        = 13UL;
  other->bank_seq        = 13UL;
  other->parent_bank_idx = 42UL;
  other->parent_bank_seq = 42UL;
  other->parent_fork     = (fd_accdb_fork_id_t){ 103 };
  FD_TEST( !strmk_block_takers( ctx, other ) );
  FD_TEST( stream->open );

  backlog_env_destroy();
}

/* A stream whose sent set has no room left for an account it just
   carried is broken, because it would skip that account next time. */

FD_UNIT_TEST( sent_set_full_breaks ) {
  backlog_env( 16UL );

  strmk_block_t * block = strmk_block_alloc( ctx );
  FD_TEST( block );
  block->slot            = 101UL;
  block->bank_idx        = 11UL;
  block->bank_seq        = 11UL;
  block->parent_bank_idx = 10UL;
  block->parent_bank_seq = 10UL;
  block->parent_fork     = (fd_accdb_fork_id_t){ 101 };
  for( ulong i=0UL; i<24UL; i++ ) {
    fd_pubkey_t key = {{ 0 }};
    FD_STORE( ulong, key.uc, fd_ulong_hash( i ) );
    FD_TEST( strmk_block_key_add( block, &key, 0 ) );
  }

  strmk_block_read( ctx, 1U, block );
  FD_TEST( stream->sent_full );
  strmk_block_flush( ctx, NULL, 1U, 1, block );
  FD_TEST( !stream->open );

  backlog_env_destroy();
}

/* A lookup table a stream already carries is expanded again, so the
   addresses it gained since are carried too. */

FD_UNIT_TEST( lookup_table_grows ) {
  backlog_env( BACKLOG_KEY_MAX );

  fd_pubkey_t table   = {{ 0x41 }};
  fd_pubkey_t addr[ 3 ] = { {{ 0x51 }}, {{ 0x52 }}, {{ 0x53 }} };
  mock_shaped_key   = table;
  mock_shaped_owner = fd_solana_address_lookup_table_program_id;
  mock_shaped_len   = FD_LOOKUP_TABLE_META_SIZE + 2UL*sizeof(fd_pubkey_t);
  mock_shaped_fork  = 0;
  memset( mock_shaped_data, 0, sizeof(mock_shaped_data) );
  memcpy( mock_shaped_data+FD_LOOKUP_TABLE_META_SIZE, addr, 2UL*sizeof(fd_pubkey_t) );
  mock_shaped = 1;

  strmk_write_account( ctx, 1U, (fd_accdb_fork_id_t){ 1 }, &table, 101UL, 0 );
  FD_TEST(  sent_test( stream, BACKLOG_KEY_MAX, &addr[ 0 ] ) );
  FD_TEST(  sent_test( stream, BACKLOG_KEY_MAX, &addr[ 1 ] ) );
  FD_TEST( !sent_test( stream, BACKLOG_KEY_MAX, &addr[ 2 ] ) );

  /* the stream knows the key it carried was a table, which is what
     makes it read it again; a plain account is not marked */
  FD_TEST(  sent_table( stream, BACKLOG_KEY_MAX, &table      ) );
  FD_TEST( !sent_table( stream, BACKLOG_KEY_MAX, &addr[ 0 ]  ) );

  /* the table gains a third address after the stream opened */
  mock_shaped_len = FD_LOOKUP_TABLE_META_SIZE + 3UL*sizeof(fd_pubkey_t);
  memcpy( mock_shaped_data+FD_LOOKUP_TABLE_META_SIZE, addr, 3UL*sizeof(fd_pubkey_t) );
  strmk_write_account( ctx, 1U, (fd_accdb_fork_id_t){ 1 }, &table, 102UL, 0 );
  FD_TEST( sent_test( stream, BACKLOG_KEY_MAX, &addr[ 2 ] ) );
  mock_shaped = 0;

  backlog_env_destroy();
}

/* A lookup table that did not exist when the stream started is carried
   as a record saying so, and the blocks that use it later still get
   its addresses: replay names it as a table it could not expand, and
   the tile reads it at the fork of the block that named it. */

FD_UNIT_TEST( table_created_after_open ) {
  backlog_env( BACKLOG_KEY_MAX );

  fd_pubkey_t table   = {{ 0x41 }};
  fd_pubkey_t addr[ 2 ] = { {{ 0x51 }}, {{ 0x52 }} };
  mock_shaped_key   = table;
  mock_shaped_owner = fd_solana_address_lookup_table_program_id;
  mock_shaped_len   = FD_LOOKUP_TABLE_META_SIZE + sizeof(addr);
  mock_shaped_fork  = 102; /* the table is created at fork 102 */
  memset( mock_shaped_data, 0, sizeof(mock_shaped_data) );
  memcpy( mock_shaped_data+FD_LOOKUP_TABLE_META_SIZE, addr, sizeof(addr) );
  mock_shaped = 1;

  /* a block whose parent fork is older than the table names it */
  strmk_block_t * before = strmk_block_alloc( ctx );
  FD_TEST( before );
  before->slot            = 101UL;
  before->bank_idx        = 11UL;
  before->bank_seq        = 11UL;
  before->parent_bank_idx = 10UL;
  before->parent_bank_seq = 10UL;
  before->parent_fork     = (fd_accdb_fork_id_t){ 101 };
  FD_TEST( strmk_block_key_add( before, &table, 1 ) );
  strmk_block_read( ctx, 1U, before );

  /* the stream carries the table as a record saying it was not there,
     so nothing marks it and nothing was expanded */
  FD_TEST(  sent_test ( stream, BACKLOG_KEY_MAX, &table     ) );
  FD_TEST( !sent_table( stream, BACKLOG_KEY_MAX, &table     ) );
  FD_TEST( !sent_test ( stream, BACKLOG_KEY_MAX, &addr[ 0 ] ) );

  /* a later block names it again, and by then it exists */
  strmk_block_t * after = strmk_block_alloc( ctx );
  FD_TEST( after );
  after->slot            = 103UL;
  after->bank_idx        = 13UL;
  after->bank_seq        = 13UL;
  after->parent_bank_idx = 11UL;
  after->parent_bank_seq = 11UL;
  after->parent_fork     = (fd_accdb_fork_id_t){ 103 };
  FD_TEST( strmk_block_key_add( after, &table, 1 ) );
  strmk_block_read( ctx, 1U, after );

  FD_TEST( sent_test( stream, BACKLOG_KEY_MAX, &addr[ 0 ] ) );
  FD_TEST( sent_test( stream, BACKLOG_KEY_MAX, &addr[ 1 ] ) );
  mock_shaped = 0;

  backlog_env_destroy();
}

/* A fork that is gone while a stream is being opened stops that
   stream and leaves the ones already being served alone. */

FD_UNIT_TEST( backlog_failure_keeps_streams ) {
  backlog_env( BACKLOG_KEY_MAX );

  /* a second stream, the one being opened */
  strmk_stream_t * opening = &ctx->stream[ 1 ];
  ctx->stream_max = 2U;
  opening->raw = mmap( NULL, STRMK_RAW_BUF_SZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( opening->raw!=MAP_FAILED );
  ulong zst_sz = ZSTD_estimateCStreamSize( FD_BACKUP_ZSTD_LEVEL );
  void * zst = aligned_alloc( 64UL, fd_ulong_align_up( zst_sz, 64UL ) );
  FD_TEST( zst );
  opening->zst = ZSTD_initStaticCStream( zst, zst_sz );
  FD_TEST( opening->zst );
  opening->sent = aligned_alloc( alignof(strmk_sent_t), BACKLOG_KEY_MAX*sizeof(strmk_sent_t) );
  FD_TEST( opening->sent );
  memset( opening->sent, 0, BACKLOG_KEY_MAX*sizeof(strmk_sent_t) );
  memset( opening->carried, 0xff, sizeof(opening->carried) );
  opening->fd        = memfd_create( "boot-stream-2", 0U );
  FD_TEST( opening->fd>=0 );
  opening->open      = 1;
  opening->published = 0;
  opening->slot_x    = TEST_SLOT_X;
  opening->bank_idx  = 10UL;
  opening->bank_seq  = 10UL;

  /* two kept blocks, the second of which chains off a bank that died */
  backlog_retain( 101UL, 11UL, 10UL );
  backlog_retain( 102UL, 12UL, 11UL );
  FD_TEST( strmk_backlog_link( ctx, TEST_SLOT_X, 10UL, 10UL ) );
  mock_bank[ 11 ]->state = FD_BANK_STATE_DEAD;

  FD_TEST( !strmk_backlog_write( ctx, NULL, 1U ) );
  FD_TEST( !opening->open );
  FD_TEST(  stream->open );

  FD_TEST( !close( opening->fd ) );
  FD_TEST( !munmap( opening->raw, STRMK_RAW_BUF_SZ ) );
  free( opening->sent );
  free( zst );
  ctx->stream_max = 1U;
  backlog_env_destroy();
}

/* A stream start from before a reset names a bank replay has already
   taken back.  The tile hands the hold back and carries on. */

FD_UNIT_TEST( stale_stream_start ) {
  backlog_env( BACKLOG_KEY_MAX );
  stream->open = 0;
  stream->closed = 0L;

  ulong seq = test_seq[ 0 ];
  fd_strmk_stream_start_t msg = { .slot = 200UL, .bank_idx = 55UL, .hold_token = 0xabcdUL };
  strmk_stream_start( ctx, test_stem, &msg, fd_log_wallclock() );
  /* the hold went back and no stream opened */
  FD_TEST( test_seq[ 0 ]==seq+1UL );
  FD_TEST( !stream->open );

  /* the same again for a bank that was handed out for another slot */
  mock_bank_add( 55UL );
  mock_bank[ 55 ]->f.slot = 199UL;
  seq = test_seq[ 0 ];
  strmk_stream_start( ctx, test_stem, &msg, fd_log_wallclock() );
  FD_TEST( test_seq[ 0 ]==seq+1UL );
  FD_TEST( !stream->open );

  /* and for a start that names no slot at all, which the sent set
     cannot tell from an empty entry */
  mock_bank[ 55 ]->f.slot = 0UL;
  msg.slot = 0UL;
  seq = test_seq[ 0 ];
  strmk_stream_start( ctx, test_stem, &msg, fd_log_wallclock() );
  FD_TEST( test_seq[ 0 ]==seq+1UL );
  FD_TEST( !stream->open );

  backlog_env_destroy();
}

/* A block start whose parent is gone is recorded all the same: the
   fork it reads at comes with the block end, and the check that it is
   still live happens there. */

FD_UNIT_TEST( stale_block_start ) {
  backlog_env( BACKLOG_KEY_MAX );

  fd_strmk_block_start_t msg = {
    .slot = 201UL, .bank_idx = 21UL, .bank_seq = 21UL,
    .parent_bank_idx = 44UL, .hold_token = 0x1234UL
  };
  strmk_block_start( ctx, test_stem, &msg );
  strmk_block_t * block = strmk_block_bank( ctx, 21UL );
  FD_TEST( block && block->bank_seq==21UL );
  FD_TEST( block->hold_token==0x1234UL );
  /* bank 44 was never made, so the fork it names is not live */
  FD_TEST( !strmk_fork_live( ctx, block ) );
  FD_TEST( stream->open );

  backlog_env_destroy();
}

/* A fork that goes away part way through a block's reads is noticed
   before the whole block has been read. */

FD_UNIT_TEST( fork_lost_mid_block ) {
  backlog_env( BACKLOG_KEY_MAX );

  strmk_block_t * block = strmk_block_alloc( ctx );
  FD_TEST( block );
  block->slot            = 101UL;
  block->bank_idx        = 11UL;
  block->bank_seq        = 11UL;
  block->parent_bank_idx = 10UL;
  block->parent_bank_seq = 10UL;
  block->parent_fork     = (fd_accdb_fork_id_t){ 101 };
  for( ulong i=0UL; i<4UL*STRMK_FORK_CHECK_KEYS; i++ ) {
    fd_pubkey_t key = {{ 0 }};
    FD_STORE( ulong, key.uc, fd_ulong_hash( i ) );
    FD_TEST( strmk_block_key_add( block, &key, 0 ) );
  }

  /* the bank dies before the reads start */
  mock_bank[ 10 ]->state = FD_BANK_STATE_DEAD;
  FD_TEST( !strmk_block_read( ctx, 1U, block ) );
  /* the reads stopped well before the whole block was read */
  FD_TEST( stream->sent_cnt<=STRMK_FORK_CHECK_KEYS );

  /* a stream that did not take the block is left alone */
  strmk_block_discard( ctx, test_stem, 0U );
  FD_TEST( stream->open );
  /* and the ones that did are broken */
  strmk_block_discard( ctx, test_stem, 1U );
  FD_TEST( !stream->open );

  backlog_env_destroy();
}

/* A closed stream's file is not handed to a new stream until a peer
   that is still downloading it has had time to notice. */

FD_UNIT_TEST( closed_slot_not_reused ) {
  backlog_env( BACKLOG_KEY_MAX );

  long now = fd_log_wallclock();
  stream->open   = 0;
  stream->closed = now;

  /* The only slot there closed a moment ago, so the start never gets
     as far as looking its bank up: it gives the hold back instead. */
  ulong seq     = test_seq[ 0 ];
  ulong queries = mock_bank_queries;
  fd_strmk_stream_start_t msg = { .slot = 200UL, .bank_idx = 55UL, .hold_token = 0xabcdUL };
  strmk_stream_start( ctx, test_stem, &msg, now );
  FD_TEST( test_seq[ 0 ]==seq+1UL ); /* the hold went back */
  FD_TEST( mock_bank_queries==queries );
  FD_TEST( !stream->open );

  /* once the wait is over the slot is free, and the start goes on to
     look the bank up */
  seq     = test_seq[ 0 ];
  queries = mock_bank_queries;
  strmk_stream_start( ctx, test_stem, &msg, now+STRMK_REUSE_NS );
  FD_TEST( test_seq[ 0 ]==seq+1UL );
  FD_TEST( mock_bank_queries>queries );
  FD_TEST( !stream->open ); /* bank 55 does not exist, a stale start */

  backlog_env_destroy();
}

/* A key message that names more keys than the link can carry is a
   broken feed, not something to read past the end of. */

FD_UNIT_TEST( key_count_guard ) {
  backlog_env( BACKLOG_KEY_MAX );

  strmk_block_t * block = strmk_block_alloc( ctx );
  FD_TEST( block );
  block->slot     = 101UL;
  block->bank_idx = 11UL;
  block->bank_seq = 11UL;

  fd_strmk_txn_keys_t msg = { .slot = 101UL, .bank_idx = 11UL, .key_cnt = (ushort)( FD_STRMK_TXN_KEY_MAX+1UL ) };
  strmk_txn_keys( ctx, test_stem, &msg, 0 );
  /* the feed was reset, so the block is gone and so is the stream */
  FD_TEST( !strmk_block_bank( ctx, 11UL ) );
  FD_TEST( !stream->open );

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
    FD_TEST( !sent_test( s, SENT_MAX, &key ) );
    FD_TEST( sent_insert( s, SENT_MAX, &key, TEST_SLOT+i, 0 ) );
    /* inserting a key the stream already carried changes nothing */
    FD_TEST( sent_insert( s, SENT_MAX, &key, TEST_SLOT+i+1UL, 0 ) );
    FD_TEST( sent_test( s, SENT_MAX, &key ) );
  }
  FD_TEST( s->sent_cnt==cap );

  /* every key is still found once the set is as full as it gets */
  for( ulong i=0UL; i<cap; i++ ) {
    fd_pubkey_t key = {{ 0 }};
    FD_STORE( ulong, key.uc,      fd_ulong_hash( i      ) );
    FD_STORE( ulong, key.uc+8UL,  fd_ulong_hash( i+1UL  ) );
    FD_STORE( ulong, key.uc+16UL, fd_ulong_hash( i+2UL  ) );
    FD_STORE( ulong, key.uc+24UL, fd_ulong_hash( i+3UL  ) );
    FD_TEST( sent_test( s, SENT_MAX, &key ) );
    FD_TEST( ( strmk_sent_query( sent, SENT_MAX, &key )->slot & ~STRMK_SENT_TABLE )==TEST_SLOT+i );
  }

  /* a set with no free entry left refuses the account that would not
     fit, which is what breaks the stream */
  for( ulong i=cap; i<SENT_MAX; i++ ) {
    fd_pubkey_t key = {{ 0 }};
    FD_STORE( ulong, key.uc, fd_ulong_hash( i ) );
    FD_TEST( sent_insert( s, SENT_MAX, &key, TEST_SLOT+i, 0 ) );
  }
  FD_TEST( s->sent_cnt==SENT_MAX );
  fd_pubkey_t over = {{ 0 }};
  FD_STORE( ulong, over.uc, fd_ulong_hash( SENT_MAX ) );
  FD_TEST( !sent_insert( s, SENT_MAX, &over, TEST_SLOT, 0 ) );
  memset( sent, 0, sizeof(sent) );
  s->sent_cnt = 0UL;
  for( ulong i=0UL; i<cap; i++ ) {
    fd_pubkey_t key = {{ 0 }};
    FD_STORE( ulong, key.uc,      fd_ulong_hash( i      ) );
    FD_STORE( ulong, key.uc+8UL,  fd_ulong_hash( i+1UL  ) );
    FD_STORE( ulong, key.uc+16UL, fd_ulong_hash( i+2UL  ) );
    FD_STORE( ulong, key.uc+24UL, fd_ulong_hash( i+3UL  ) );
    FD_TEST( sent_insert( s, SENT_MAX, &key, TEST_SLOT+i, 0 ) );
  }

  /* a key the stream never carried is not in the set */
  for( ulong i=cap; i<cap+64UL; i++ ) {
    fd_pubkey_t key = {{ 0 }};
    FD_STORE( ulong, key.uc,      fd_ulong_hash( i      ) );
    FD_STORE( ulong, key.uc+8UL,  fd_ulong_hash( i+1UL  ) );
    FD_STORE( ulong, key.uc+16UL, fd_ulong_hash( i+2UL  ) );
    FD_STORE( ulong, key.uc+24UL, fd_ulong_hash( i+3UL  ) );
    FD_TEST( !sent_test( s, SENT_MAX, &key ) );
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
