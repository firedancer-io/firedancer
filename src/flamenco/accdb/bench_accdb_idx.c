#define _GNU_SOURCE

/* bench_accdb_idx compares accdb operations with and without the disk
   index.  It builds against trees without the disk index too (detected
   by FD_ACCDB_IDX_FD_RW), so the same phases can be timed on main.

   Phases: full snapshot load (incl. index build), cold reads after
   dropping the page cache, hot reads, reads of missing accounts, and
   replay-style writes that root every slot. */

#include "fd_accdb.h"
#include "fd_accdb_private.h"
#include "../../util/fd_util.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef FD_ACCDB_IDX_FD_RW
#define IDX_ARG(x) , (x)
#else
#define IDX_ARG(x)
#endif

#define DATA_SZ (128UL)

static uchar owner[ 32 ] = { 0xEE };

static void
make_pubkey( uchar pk[ 32 ],
             ulong i ) {
  fd_memset( pk, 0, 32UL );
  ulong h = fd_ulong_hash( i );
  fd_memcpy( pk, &h, 8UL );
  fd_memcpy( pk+8, &i, 8UL );
}

typedef struct { fd_accdb_t * accdb; int stop; } bg_t;

#ifdef FD_ACCDB_IDX_FD_RW
typedef struct { fd_accdb_t * accdb; void * scratch; } build_t;

static void *
build_run( void * arg ) {
  build_t * b = arg;
  fd_accdb_snapshot_index_build_work( b->accdb, b->scratch );
  return NULL;
}
#endif

static void *
bg_run( void * arg ) {
  bg_t * bg = arg;
  while( !FD_VOLATILE_CONST( bg->stop ) ) {
    int busy = 0;
    fd_accdb_background( bg->accdb, &busy );
    if( !busy ) FD_SPIN_PAUSE();
  }
  return NULL;
}

static double
now_s( void ) {
  return (double)fd_log_wallclock()*1e-9;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  ulong        n         = fd_env_strip_cmdline_ulong( &argc, &argv, "--accounts",      NULL, 4000000UL );
  ulong        ram_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--index-ram-max", NULL,       0UL );
  ulong        cold_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--cold",          NULL,  200000UL );
  ulong        slot_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--slots",         NULL,     300UL );
  ulong        slot_wr   = fd_env_strip_cmdline_ulong( &argc, &argv, "--slot-writes",   NULL,    2000UL );
  char const * dir       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--dir",           NULL,    "/tmp" );
  ulong        hot_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--hot",           NULL, 2000000UL );
  ulong        max_accts = fd_env_strip_cmdline_ulong( &argc, &argv, "--max-accounts",  NULL,       0UL );
  ulong        workers   = fd_env_strip_cmdline_ulong( &argc, &argv, "--workers",       NULL,       1UL );
  FD_TEST( workers>=1UL && workers<=32UL );
#ifndef FD_ACCDB_IDX_FD_RW
  if( ram_max ) FD_LOG_ERR(( "this tree has no disk index" ));
#endif

  ulong max_accounts = max_accts ? max_accts : n+n/8UL;
  ulong cache_fp     = 512UL<<20;
  ulong min_res      = 4UL;

  /* Mainnet-scale shmem footprint (the index part dominates). */
  ulong mainnet_fp = fd_accdb_shmem_footprint( 1300000000UL, 2048UL, 321280UL, 8192UL, 12UL<<30, 640UL, 32UL, 0UL IDX_ARG( ram_max ? 33554432UL : 0UL ) );
  FD_LOG_NOTICE(( "mainnet-scale accdb shmem footprint: %.2f GiB", (double)mainnet_fp/(double)(1UL<<30) ));

  char path[ 512 ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/bench_accdb.db", dir ) );
  int fd = open( path, O_RDWR|O_CREAT|O_TRUNC, 0600 );
  FD_TEST( fd>=0 );
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/bench_accdb.db-index", dir ) );
  int idx_fd = open( path, O_RDWR|O_CREAT|O_TRUNC, 0600 );
  FD_TEST( idx_fd>=0 );

  ulong shmem_fp = fd_accdb_shmem_footprint( max_accounts, 64UL, 8192UL, 64UL, cache_fp, min_res, 1UL+workers, 0UL IDX_ARG( ram_max ) );
  FD_TEST( shmem_fp );
  FD_LOG_NOTICE(( "accounts=%lu index_ram_max=%lu shmem footprint %.1f MiB", n, ram_max, (double)shmem_fp/(double)(1UL<<20) ));
  void * shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_fp );
  FD_TEST( shmem_mem );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join( fd_accdb_shmem_new( shmem_mem, max_accounts, 64UL, 8192UL, 64UL, 1UL<<30,
                                                                      cache_fp, min_res, 0, 42UL, 1UL+workers, 0UL IDX_ARG( ram_max ) ) );
  FD_TEST( shmem );
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( aligned_alloc( fd_accdb_align(), fd_accdb_footprint( 64UL, 0 ) ), shmem, fd, 0UL, NULL, NULL, 0UL, 0 ) );
  fd_accdb_t * t2    = fd_accdb_join( fd_accdb_new( aligned_alloc( fd_accdb_align(), fd_accdb_footprint( 64UL, 1 ) ), shmem, fd, 0UL, NULL, NULL, 0UL, 1 ) );
  FD_TEST( accdb && t2 );
#ifdef FD_ACCDB_IDX_FD_RW
  fd_accdb_set_index_fd( accdb, idx_fd );
  fd_accdb_set_index_fd( t2,    idx_fd );
#endif
  fd_accdb_fork_id_t root = fd_accdb_attach_child( accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );

  /* Full snapshot load: 8 records per batch. */
  static uchar rec[ 8UL*(sizeof(fd_accdb_disk_meta_t)+DATA_SZ) ];
  uchar pks[ 8 ][ 32 ];
  double t0 = now_s();
  fd_accdb_snapshot_load_begin( accdb );
  for( ulong i=0UL; i<n; i+=8UL ) {
    ulong cnt = fd_ulong_min( 8UL, n-i );
    ulong sz  = cnt*(sizeof(fd_accdb_disk_meta_t)+DATA_SZ);
    ulong off = fd_accdb_snapshot_reserve_write( accdb, sz, 0UL );
    uchar const * pk[ 8 ]; ulong slots[ 8 ], lamports[ 8 ], lens[ 8 ], offs[ 8 ]; int exec[ 8 ] = {0};
    for( ulong j=0UL; j<cnt; j++ ) {
      make_pubkey( pks[ j ], i+j );
      fd_accdb_disk_meta_t * m = (fd_accdb_disk_meta_t *)( rec+j*(sizeof(fd_accdb_disk_meta_t)+DATA_SZ) );
      fd_memcpy( m->pubkey, pks[ j ], 32UL );
      m->size = (uint)DATA_SZ; m->generation = 0U;
      fd_memcpy( m->owner, owner, 32UL );
      fd_memset( m+1, (int)(uchar)(i+j), DATA_SZ );
      pk[ j ] = pks[ j ]; slots[ j ] = 1UL; lamports[ j ] = 1000UL+i+j; lens[ j ] = DATA_SZ;
      offs[ j ] = off+j*(sizeof(fd_accdb_disk_meta_t)+DATA_SZ);
    }
    FD_TEST( pwrite( fd, rec, sz, (long)off )==(long)sz );
    ulong ign, rep, ld, rl, il; uchar res[ 8 ];
    FD_TEST( !fd_accdb_snapshot_write_batch( accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX }, cnt, pk, slots, lamports, lens, exec, offs,
                                             &ign, &rep, &ld, &rl, &il, res ) );
  }
#ifdef FD_ACCDB_IDX_FD_RW
  /* The main thread finishes the build, workers-1 threads help. */
  ulong     scratch_sz = fd_accdb_snapshot_index_build_scratch_footprint( max_accounts, ram_max );
  build_t   helpers[ 32 ];
  pthread_t helper_threads[ 32 ];
  for( ulong w=1UL; w<workers; w++ ) {
    helpers[ w ].accdb   = fd_accdb_join( fd_accdb_new( aligned_alloc( fd_accdb_align(), fd_accdb_footprint( 64UL, 0 ) ), shmem, fd, 0UL, NULL, NULL, 0UL, 0 ) );
    helpers[ w ].scratch = aligned_alloc( fd_accdb_snapshot_index_build_scratch_align(), fd_ulong_max( scratch_sz, fd_accdb_snapshot_index_build_scratch_align() ) );
    FD_TEST( helpers[ w ].accdb && helpers[ w ].scratch );
    fd_accdb_set_index_fd( helpers[ w ].accdb, idx_fd );
    FD_TEST( !pthread_create( &helper_threads[ w ], NULL, build_run, &helpers[ w ] ) );
  }
  void * scratch = aligned_alloc( fd_accdb_snapshot_index_build_scratch_align(), fd_ulong_max( scratch_sz, fd_accdb_snapshot_index_build_scratch_align() ) );
  FD_TEST( scratch );
  ulong dup_cnt, dup_lamports;
  double tb = now_s();
  fd_accdb_snapshot_index_build_fini( accdb, scratch, &dup_cnt, &dup_lamports );
  FD_LOG_NOTICE(( "index build: %lu workers in %.2f s", workers, now_s()-tb ));
  for( ulong w=1UL; w<workers; w++ ) FD_TEST( !pthread_join( helper_threads[ w ], NULL ) );
#endif
  fd_accdb_snapshot_load_end( accdb );
  double dt = now_s()-t0;
  FD_LOG_NOTICE(( "load:  %lu accounts in %.2f s (%.0f ns/account)", n, dt, dt*1e9/(double)n ));

  bg_t bg = { .accdb = t2 };
  pthread_t thread;
  FD_TEST( !pthread_create( &thread, NULL, bg_run, &bg ) );

  /* Cold reads: distinct accounts, page cache dropped. */
  fsync( fd ); fsync( idx_fd );
  FD_TEST( !posix_fadvise( fd,     0, 0, POSIX_FADV_DONTNEED ) );
  FD_TEST( !posix_fadvise( idx_fd, 0, 0, POSIX_FADV_DONTNEED ) );
  uchar pk[ 32 ];
  uchar const * pkp[ 1 ] = { pk };
  int wr[ 1 ] = { 0 };
  fd_acc_t acc[ 1 ];
  t0 = now_s();
  for( ulong i=0UL; i<cold_cnt; i++ ) {
    ulong a = ( i*2654435761UL )%n;
    make_pubkey( pk, a );
    fd_accdb_acquire( accdb, root, 1UL, pkp, wr, acc );
    if( FD_UNLIKELY( acc->lamports!=1000UL+a || acc->data[ 0 ]!=(uchar)a ) ) {
      ulong o = 0UL, l = 0UL; int q = -1;
#ifdef FD_ACCDB_IDX_FD_RW
      uint sz;
      q = fd_accdb_idx_query( accdb, pk, &o, &l, &sz );
#endif
      FD_LOG_ERR(( "cold read %lu: account %lu lamports %lu (want %lu) data_len %lu data[0] %u (want %u) idx_query %d off %lu lamports %lu",
                   i, a, acc->lamports, 1000UL+a, acc->data_len, acc->data ? acc->data[ 0 ] : 999U, (uint)(uchar)a, q, o, l ));
    }
    fd_accdb_release( accdb, 1UL, acc );
  }
  dt = now_s()-t0;
  FD_LOG_NOTICE(( "cold:  %.0f ns/read (%lu reads)", dt*1e9/(double)cold_cnt, cold_cnt ));

  /* Hot reads: 1000 accounts, repeated. */
  t0 = now_s();
  for( ulong i=0UL; i<hot_cnt; i++ ) {
    ulong a = ( (i%1000UL)*7919UL )%n;
    make_pubkey( pk, a );
    fd_accdb_acquire( accdb, root, 1UL, pkp, wr, acc );
    fd_accdb_release( accdb, 1UL, acc );
  }
  dt = now_s()-t0;
  FD_LOG_NOTICE(( "hot:   %.0f ns/read", dt*1e9/(double)hot_cnt ));

  /* Missing accounts through the read-only path. */
  ulong miss_cnt = 1000000UL;
  t0 = now_s();
  for( ulong i=0UL; i<miss_cnt; i++ ) {
    make_pubkey( pk, n+i );
    FD_TEST( !fd_accdb_lamports( accdb, root, pk ) );
  }
  dt = now_s()-t0;
  FD_LOG_NOTICE(( "miss:  %.0f ns/lookup", dt*1e9/(double)miss_cnt ));

  /* Replay-style writes: random accounts, root every slot. */
  int ww[ 1 ] = { 1 };
  t0 = now_s();
  for( ulong s=0UL; s<slot_cnt; s++ ) {
    fd_accdb_fork_id_t f = fd_accdb_attach_child( accdb, root );
    for( ulong i=0UL; i<slot_wr; i++ ) {
      ulong a = fd_ulong_hash( s*slot_wr+i )%n;
      make_pubkey( pk, a );
      fd_accdb_acquire( accdb, f, 1UL, pkp, ww, acc );
      acc->lamports++;
      acc->commit = 1;
      fd_accdb_release( accdb, 1UL, acc );
    }
    fd_accdb_advance_root( accdb, f );
    root = f;
  }
  while( fd_accdb_cmd_pending( accdb ) ) FD_SPIN_PAUSE();
  dt = now_s()-t0;
  FD_LOG_NOTICE(( "write: %.0f ns/write (%lu slots x %lu writes, root every slot)", dt*1e9/(double)(slot_cnt*slot_wr), slot_cnt, slot_wr ));
#ifdef FD_ACCDB_IDX_FD_RW
  FD_LOG_NOTICE(( "index RAM entries in use: %lu of %lu", FD_VOLATILE_CONST( shmem->acc_used.val ), shmem->pool_max ));
#endif

  FD_VOLATILE( bg.stop ) = 1;
  FD_TEST( !pthread_join( thread, NULL ) );
  close( fd ); close( idx_fd );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
