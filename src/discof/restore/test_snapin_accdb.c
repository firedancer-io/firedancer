#define _GNU_SOURCE

#include "../../util/archive/fd_tar.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fd_snapin_tile.c"

#define TEST_APPENDVEC_CNT   (9UL)
#define TEST_ACCOUNT_CNT     (FD_SSPARSE_ACC_BATCH_MAX+TEST_APPENDVEC_CNT-1UL)
#define TEST_WORKER_MAX      (9UL)
#define TEST_MAX_ACCOUNTS    (65536UL)
#define TEST_PARTITION_SZ    (11UL<<20)
#define TEST_CACHE_FOOTPRINT (32UL<<20)

typedef struct {
  uchar pubkey[ 32UL ];
  uchar owner [ 32UL ];
  ulong lamports;
  int   executable;
  ulong data_len;
  uchar data[ 64UL ];
} test_account_t;

typedef struct {
  ulong                    worker_cnt;
  void *                   shmem_mem;
  fd_accdb_shmem_t *       shmem;
  void *                   snoop_mem;
  fd_snapio_snoop_hdr_t *  snoop;
  fd_snapin_tile_t *       worker;
  void *                   join_mem [ TEST_WORKER_MAX ];
  uchar *                  write_buf[ TEST_WORKER_MAX ];
  fd_accdb_fork_id_t       root;
} test_env_t;

static void
tar_header( uchar *      buf,
            char const * name,
            ulong        data_sz ) {
  FD_TEST( fd_tar_meta_init_file_default( (fd_tar_meta_t *)buf, name, data_sz, 1700000000L*1000000000L ) );
}

static ulong
tar_entry( uchar *       tar,
           ulong         tar_max,
           ulong         off,
           char const *  name,
           uchar const * data,
           ulong         data_sz ) {
  ulong padded = fd_ulong_align_up( data_sz, 512UL );
  FD_TEST( off+512UL+padded<=tar_max );
  tar_header( tar+off, name, data_sz );
  off += 512UL;
  if( data_sz ) fd_memcpy( tar+off, data, data_sz );
  fd_memset( tar+off+data_sz, 0, padded-data_sz );
  return off+padded;
}

static ulong
appendvec_account( uchar *                dst,
                   test_account_t const * account ) {
  ulong sz = fd_ulong_align_up( 136UL+account->data_len, 8UL );
  fd_memset( dst, 0, sz );
  FD_STORE( ulong, dst,      account->lamports );
  FD_STORE( ulong, dst+8UL,  account->data_len );
  fd_memcpy( dst+16UL, account->pubkey, 32UL );
  FD_STORE( ulong, dst+48UL, account->lamports );
  fd_memcpy( dst+64UL, account->owner, 32UL );
  dst[ 96UL ] = (uchar)account->executable;
  fd_memcpy( dst+136UL, account->data, account->data_len );
  return sz;
}

static ulong
build_snapshot( uchar *          tar,
                ulong            tar_max,
                test_account_t const * accounts ) {
  uchar batch_body[ FD_SSPARSE_ACC_BATCH_MAX*136UL ];
  ulong batch_sz = 0UL;
  for( ulong i=0UL; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {
    batch_sz += appendvec_account( batch_body+batch_sz, &accounts[ i ] );
  }

  uchar metadata = 0xA5U;

  ulong off = 0UL;
  off = tar_entry( tar, tar_max, off, "version",                (uchar const *)"1.2.0", 5UL );
  off = tar_entry( tar, tar_max, off, "snapshots/500/500",      &metadata,              1UL );
  off = tar_entry( tar, tar_max, off, "accounts/100.0",         batch_body,             batch_sz );
  for( ulong av=1UL; av<TEST_APPENDVEC_CNT; av++ ) {
    uchar body[ 256UL ];
    ulong body_sz = appendvec_account( body, &accounts[ FD_SSPARSE_ACC_BATCH_MAX+av-1UL ] );
    char name[ 64UL ];
    FD_TEST( fd_cstr_printf_check( name, sizeof(name), NULL, "accounts/%lu.%lu", 100UL+av, av ) );
    off = tar_entry( tar, tar_max, off, name, body, body_sz );
  }
  off = tar_entry( tar, tar_max, off, "snapshots/status_cache", &metadata,              1UL );
  FD_TEST( off+1024UL<=tar_max );
  fd_memset( tar+off, 0, 1024UL );
  return off+1024UL;
}

static void
test_env_init( test_env_t * env,
               ulong        worker_cnt ) {
  FD_TEST( worker_cnt==1UL || worker_cnt==9UL );
  fd_memset( env, 0, sizeof(*env) );
  env->worker_cnt = worker_cnt;

  int fd = memfd_create( "snapin_accdb", 0 );
  FD_TEST( fd>=0 );
  FD_TEST( dup2( fd, FD_ACCDB_FD_RW )==FD_ACCDB_FD_RW );
  if( fd!=FD_ACCDB_FD_RW ) FD_TEST( !close( fd ) );
  struct stat st;
  FD_TEST( !fstat( FD_ACCDB_FD_RW, &st ) );
  FD_TEST( S_ISREG( st.st_mode ) );

  ulong shmem_fp = fd_accdb_shmem_footprint( TEST_MAX_ACCOUNTS, 16UL, 128UL, 32UL,
                                             TEST_CACHE_FOOTPRINT, 2UL,
                                             worker_cnt, 0UL );
  env->shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_fp );
  FD_TEST( env->shmem_mem );
  env->shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( env->shmem_mem, TEST_MAX_ACCOUNTS, 16UL, 128UL, 32UL,
                          TEST_PARTITION_SZ, TEST_CACHE_FOOTPRINT, 2UL,
                          0, 42UL, worker_cnt, 0UL ) );
  FD_TEST( env->shmem );

  ulong snoop_fp = fd_snapio_snoop_footprint( worker_cnt );
  env->snoop_mem = aligned_alloc( fd_snapio_snoop_align(),
                                  fd_ulong_align_up( snoop_fp, fd_snapio_snoop_align() ) );
  FD_TEST( env->snoop_mem );
  env->snoop = fd_snapio_snoop_join( fd_snapio_snoop_new( env->snoop_mem, worker_cnt ) );
  FD_TEST( env->snoop );

  ulong worker_fp = fd_ulong_align_up( worker_cnt*sizeof(fd_snapin_tile_t), alignof(fd_snapin_tile_t) );
  env->worker = aligned_alloc( alignof(fd_snapin_tile_t), worker_fp );
  FD_TEST( env->worker );
  fd_memset( env->worker, 0, worker_fp );

  for( ulong i=0UL; i<worker_cnt; i++ ) {
    ulong join_fp = fd_accdb_footprint( 16UL );
    env->join_mem[ i ] = aligned_alloc( fd_accdb_align(), join_fp );
    FD_TEST( env->join_mem[ i ] );

    fd_snapin_tile_t * ctx = &env->worker[ i ];
    ctx->accdb = fd_accdb_join( fd_accdb_new( env->join_mem[ i ], env->shmem,
                                               FD_ACCDB_FD_RW, 0UL, NULL ) );
    FD_TEST( ctx->accdb );
    ctx->full         = 1;
    ctx->tile_idx     = i;
    ctx->tile_cnt     = worker_cnt;
    ctx->stripe_locks = fd_snapio_snoop_stripes( env->snoop );
    ctx->snoop_hdr    = env->snoop;
    ctx->my_snoop     = fd_snapio_snoop_worker( env->snoop, i );
    ctx->whead.attempt_partitions    = ctx->my_snoop->fail_partitions;
    ctx->whead.attempt_partition_max = FD_SNAPIO_FAIL_PARTITION_MAX;

    env->write_buf[ i ] = aligned_alloc( 4096UL, FD_SNAPIN_WRITE_BUF_SZ );
    FD_TEST( env->write_buf[ i ] );
    writer_init( &ctx->writer, FD_ACCDB_FD_RW, env->write_buf[ i ], 0UL, FD_SNAPIN_WB_KICK_SZ );
  }

  env->root = fd_accdb_attach_child( env->worker[ 0 ].accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  fd_accdb_snapshot_load_begin( env->worker[ 0 ].accdb );
  for( ulong i=0UL; i<worker_cnt; i++ ) {
    writer_begin( &env->worker[ i ].writer );
    fd_accdb_snapshot_writer_begin( env->worker[ i ].accdb );
  }
}

static void
dispatch_snapshot( test_env_t *  env,
                   uchar const * tar,
                   ulong         tar_sz ) {
  fd_ssparse_t parser[ 1 ];
  fd_ssparse_init( parser );
  fd_ssparse_batch_enable( parser, 1 );
  fd_ssparse_appendvec_passthrough_enable( parser, 1 );

  fd_snapin_tile_t * owner = NULL;
  ulong off                = 0UL;
  ulong appendvec_cnt      = 0UL;
  ulong batch_cnt          = 0UL;
  ulong batch_account_cnt  = 0UL;
  ulong header_cnt         = 0UL;
  ulong header_fragment_cnt = 0UL;
  ulong data_cnt           = 0UL;
  ulong zero_progress      = 0UL;
  int   fragment_account   = 0;
  int   awaiting_header    = 0;
  int   done               = 0;

  while( off<tar_sz ) {
    ulong feed_sz = fragment_account ? fd_ulong_min( 11UL, tar_sz-off ) : tar_sz-off;
    fd_ssparse_advance_result_t result[ 1 ];
    int res = fd_ssparse_advance( parser, tar+off, feed_sz, result );
    FD_TEST( res!=FD_SSPARSE_ADVANCE_ERROR );
    FD_TEST( result->bytes_consumed<=feed_sz );

    switch( res ) {
      case FD_SSPARSE_ADVANCE_APPENDVEC:
        FD_TEST( appendvec_cnt<TEST_APPENDVEC_CNT );
        owner = &env->worker[ appendvec_cnt%env->worker_cnt ];
        fd_ssparse_appendvec_parse( parser );
        appendvec_cnt++;
        fragment_account = appendvec_cnt==2UL;
        awaiting_header  = fragment_account;
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_BATCH:
        FD_TEST( owner );
        FD_TEST( !worker_process_account_batch( owner, result ) );
        batch_cnt++;
        batch_account_cnt += result->account_batch.batch_cnt;
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_HEADER:
        FD_TEST( owner );
        FD_TEST( !worker_process_account_header( owner, result ) );
        awaiting_header = 0;
        header_cnt++;
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_DATA:
        FD_TEST( owner );
        FD_TEST( !worker_process_account_data( owner, result ) );
        data_cnt++;
        break;
      case FD_SSPARSE_ADVANCE_DONE:
        done = 1;
        break;
      default:
        break;
    }
    if( awaiting_header && res==FD_SSPARSE_ADVANCE_AGAIN && result->bytes_consumed ) header_fragment_cnt++;

    off += result->bytes_consumed;
    if( result->bytes_consumed ) zero_progress = 0UL;
    else                         FD_TEST( ++zero_progress<1024UL );
    if( done ) break;
  }

  FD_TEST( done );
  FD_TEST( off==tar_sz );
  FD_TEST( appendvec_cnt==TEST_APPENDVEC_CNT );
  FD_TEST( batch_cnt==1UL );
  FD_TEST( batch_account_cnt==FD_SSPARSE_ACC_BATCH_MAX );
  FD_TEST( header_cnt==TEST_APPENDVEC_CNT-1UL );
  FD_TEST( header_fragment_cnt>1UL );
  FD_TEST( data_cnt>1UL );
}

static void
read_account( test_env_t *          env,
              test_account_t const * expected ) {
  uchar const * pubkeys[ 1 ] = { expected->pubkey };
  int           writable[ 1 ] = { 0 };
  fd_acc_t      account[ 1 ];
  fd_memset( account, 0, sizeof(account) );

  fd_accdb_acquire( env->worker[ 0 ].accdb, env->root, 1UL, pubkeys, writable, account );
  FD_TEST( fd_memeq( account->pubkey, expected->pubkey, 32UL ) );
  FD_TEST( fd_memeq( account->owner,  expected->owner,  32UL ) );
  FD_TEST( account->lamports==expected->lamports );
  FD_TEST( account->executable==expected->executable );
  FD_TEST( account->data_len==expected->data_len );
  if( expected->data_len ) FD_TEST( fd_memeq( account->data, expected->data, expected->data_len ) );
  fd_accdb_release( env->worker[ 0 ].accdb, 1UL, account );
}

static void
test_env_fini( test_env_t *          env,
               test_account_t const * accounts ) {
  ulong bytes_written = 0UL;
  for( ulong i=0UL; i<env->worker_cnt; i++ ) {
    fd_snapin_tile_t * ctx = &env->worker[ i ];
    FD_TEST( !writer_end( &ctx->writer ) );
    bytes_written += ctx->writer.bytes_written;
    fd_accdb_snapshot_worker_close( ctx->accdb, &ctx->whead );
    fd_accdb_snapshot_writer_end( ctx->accdb );
    fd_accdb_snapshot_flush_worker_metrics( ctx->accdb, ctx->worker_metrics );
  }

  ulong expected_bytes = TEST_ACCOUNT_CNT*sizeof(fd_accdb_disk_meta_t)+accounts[ FD_SSPARSE_ACC_BATCH_MAX ].data_len;
  FD_TEST( bytes_written==expected_bytes );
  if( env->worker_cnt==1UL ) {
    FD_TEST( env->worker[ 0 ].writer.bytes_written==expected_bytes );
  } else {
    FD_TEST( env->worker[ 0 ].writer.bytes_written==FD_SSPARSE_ACC_BATCH_MAX*sizeof(fd_accdb_disk_meta_t) );
    FD_TEST( env->worker[ 1 ].writer.bytes_written==sizeof(fd_accdb_disk_meta_t)+accounts[ FD_SSPARSE_ACC_BATCH_MAX ].data_len );
    for( ulong i=2UL; i<env->worker_cnt; i++ ) FD_TEST( env->worker[ i ].writer.bytes_written==sizeof(fd_accdb_disk_meta_t) );
  }

  fd_accdb_snapshot_load_end( env->worker[ 0 ].accdb );
  fd_accdb_snapshot_verify_readback( env->worker[ 0 ].accdb, ULONG_MAX );
  for( ulong i=0UL; i<TEST_ACCOUNT_CNT; i++ ) read_account( env, &accounts[ i ] );

  for( ulong i=0UL; i<env->worker_cnt; i++ ) {
    free( env->write_buf[ i ] );
    free( env->join_mem[ i ] );
  }
  free( env->worker );
  free( env->snoop_mem );
  free( env->shmem_mem );
  FD_TEST( !close( FD_ACCDB_FD_RW ) );
}

static void
test_snapin_accdb( ulong worker_cnt ) {
  test_account_t accounts[ TEST_ACCOUNT_CNT ];
  fd_memset( accounts, 0, sizeof(accounts) );
  for( ulong i=0UL; i<TEST_ACCOUNT_CNT; i++ ) {
    accounts[ i ].pubkey[ 0 ] = (uchar)(i+1UL);
    accounts[ i ].pubkey[ 31 ] = 0xC3U;
    accounts[ i ].owner[ 0 ] = (uchar)(0x80UL+i);
    accounts[ i ].owner[ 31 ] = 0x5AU;
    accounts[ i ].lamports   = 1000UL+i;
    accounts[ i ].executable = (int)(i&1UL);
  }
  accounts[ FD_SSPARSE_ACC_BATCH_MAX ].data_len = 37UL;
  accounts[ FD_SSPARSE_ACC_BATCH_MAX ].executable = 1;
  for( ulong i=0UL; i<accounts[ FD_SSPARSE_ACC_BATCH_MAX ].data_len; i++ ) {
    accounts[ FD_SSPARSE_ACC_BATCH_MAX ].data[ i ] = (uchar)(0x40UL+i);
  }

  uchar tar[ 16384UL ];
  ulong tar_sz = build_snapshot( tar, sizeof(tar), accounts );

  test_env_t env[ 1 ];
  test_env_init( env, worker_cnt );
  dispatch_snapshot( env, tar, tar_sz );
  test_env_fini( env, accounts );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_snapin_accdb( 1UL );
  test_snapin_accdb( 9UL );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
