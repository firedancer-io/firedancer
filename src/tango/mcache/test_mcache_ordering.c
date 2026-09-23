/* Exercise both directions of a reliable shared-memory link: payload and
   metadata publication, and read completion before buffer reuse.  A pass
   is a stress check, not a proof of correctness under a weak memory model. */

#define _GNU_SOURCE
#include "fd_mcache.h"
#include "../fseq/fd_fseq.h"
#include <pthread.h>
#include <sched.h>

#define DEPTH (128UL)
#define CNT   (1000000UL)
#define SEQ0  (ULONG_MAX-1023UL)

static uchar mcache_mem[ FD_MCACHE_FOOTPRINT( DEPTH, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar fseq_mem[ FD_FSEQ_FOOTPRINT ] __attribute__((aligned(FD_FSEQ_ALIGN)));
static ulong payload[ DEPTH ][ 16 ] __attribute__((aligned(128)));
static fd_frag_meta_t * mcache;
static ulong * fseq;
static cpu_set_t producer_cpus;

static void *
producer( void * arg ) {
  (void)arg;
  FD_TEST( !pthread_setaffinity_np( pthread_self(), sizeof(producer_cpus), &producer_cpus ) );
  for( ulong i=0UL; i<CNT; i++ ) {
    ulong seq = fd_seq_inc( SEQ0, i );
    while( fd_seq_diff( seq, fd_fseq_query( fseq ) )>=(long)DEPTH ) FD_SPIN_PAUSE();
    ulong chunk = i & (DEPTH-1UL);
    for( ulong j=0UL; j<16UL; j++ ) payload[ chunk ][ j ] = seq ^ (j*0x9e3779b97f4a7c15UL);
    fd_mcache_publish( mcache, DEPTH, seq, seq, chunk, 128UL, i & 65535UL, (uint)seq, (uint)~seq );
  }
  return NULL;
}

int
main( int argc, char ** argv ) {
  /* Capture allowed CPUs before fd_boot pins the main thread.  Otherwise
     pthread_create inherits that pin and this would test only one core. */
  cpu_set_t allowed;
  FD_TEST( !sched_getaffinity( 0, sizeof(allowed), &allowed ) );
  int reader_cpu = -1;
  int writer_cpu = -1;
  for( int cpu=0; cpu<CPU_SETSIZE; cpu++ ) {
    if( !CPU_ISSET( (ulong)cpu, &allowed ) ) continue;
    if( reader_cpu<0 ) reader_cpu = cpu;
    else { writer_cpu = cpu; break; }
  }
  fd_boot( &argc, &argv );
  FD_TEST( reader_cpu>=0 && writer_cpu>=0 );
  cpu_set_t reader_cpus;
  CPU_ZERO( &reader_cpus );
  CPU_SET( (ulong)reader_cpu, &reader_cpus );
  CPU_ZERO( &producer_cpus );
  CPU_SET( (ulong)writer_cpu, &producer_cpus );
  FD_TEST( !pthread_setaffinity_np( pthread_self(), sizeof(reader_cpus), &reader_cpus ) );
  FD_LOG_NOTICE(( "reader CPU %i, writer CPU %i", reader_cpu, writer_cpu ));
  mcache = fd_mcache_join( fd_mcache_new( mcache_mem, DEPTH, 0UL, SEQ0 ) );
  fseq   = fd_fseq_join( fd_fseq_new( fseq_mem, SEQ0 ) );
  FD_TEST( mcache && fseq );
  pthread_t thread;
  FD_TEST( !pthread_create( &thread, NULL, producer, NULL ) );
  for( ulong i=0UL; i<CNT; i++ ) {
    ulong seq = fd_seq_inc( SEQ0, i );
    fd_frag_meta_t meta;
    fd_frag_meta_t const * line;
    ulong found;
    long diff;
    ulong poll_max = ULONG_MAX;
    FD_MCACHE_WAIT( &meta, line, found, diff, poll_max, mcache, DEPTH, seq );
    FD_TEST( poll_max && !diff && found==seq );
    FD_TEST( meta.sig==seq && meta.chunk==(i & (DEPTH-1UL)) );
    FD_TEST( meta.sz==128UL && meta.ctl==(i & 65535UL) );
    FD_TEST( meta.tsorig==(uint)seq && meta.tspub==(uint)~seq );
    for( ulong j=0UL; j<16UL; j++ ) FD_TEST( payload[ meta.chunk ][ j ]==(seq ^ (j*0x9e3779b97f4a7c15UL)) );
    FD_HW_MFENCE_LD();
    FD_TEST( __atomic_load_n( &line->seq, __ATOMIC_RELAXED )==seq );
    fd_fseq_update( fseq, fd_seq_inc( seq, 1UL ) );
  }
  FD_TEST( !pthread_join( thread, NULL ) );
  FD_TEST( fd_mcache_delete( fd_mcache_leave( mcache ) )==mcache_mem );
  FD_TEST( fd_fseq_delete( fd_fseq_leave( fseq ) )==fseq_mem );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
