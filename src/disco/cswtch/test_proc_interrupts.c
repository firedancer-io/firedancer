#if !defined(__linux__)
#error "This test requires Linux"
#endif

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h> /* open */
#include <sys/mman.h> /* memfd_create */
#include <unistd.h> /* lseek, close */

#include "fd_proc_interrupts.h"
#include "../../util/fd_util.h"

ulong per_cpu[ 3 ][ FD_TILE_MAX ];

FD_IMPORT_BINARY( example_interrupts, "src/disco/cswtch/example_proc_interrupts.txt" );
static ulong example_interrupts_counters[ 64 ] = {
/*  CPU0    CPU1    CPU2    CPU3    CPU4    CPU5    CPU6    CPU7 */
    9539,      0,      0,      0,      0,      0,    370,      0,
       0,      0,      0,      0,      0,      0,2432444,      0,
       0,      0,      0,      0,      0,  11681,      0,      0,
       0,      0,      0,      0,      0,      0,      0,      0,
       0,      0,      0,    118,    112,     96,5577193,   3048,
       6,   7375,      0, 410971,      0,      0,    136,    442,
     923,     58,      0,      0,      0,      0,      0,      0,
     309,      0,3192699,    305,      0,      0,1018238,      0
};

FD_IMPORT_BINARY( example_softirqs, "src/disco/cswtch/example_proc_softirqs.txt" );
static ulong example_softirqs_counters[ 3 ][ 64 ] = {
/*    CPU0     CPU1     CPU2     CPU3     CPU4     CPU5     CPU6     CPU7 */
  {  17282,   54243,12970165,  465736,  153112,  271197,  128202,  159750,
     82245,  432575,       0, 1468547,  152115,  123019, 2472814, 1369549,
    208710, 3299397,  528714,   76794,   61223, 2266050,  146325,  134915,
    265723,  130172,  312533,  155390,  124326,  141355,  358141,  164461,
     99737,   71330,13097744,   61978,  115027,  382110,   45887,  162044,
    220310,  348796,  271308, 1049998,  146384,  384016,  197883,  331416,
    237293,  153215,  151854, 3228595,  146541, 3311956,  112723, 6492554,
    122606,  130720, 4122483,  188044,  262274,  267550,  217152,  141782  },
  {  57274,  130540,  131698,  116232,   27109,   48453,   16636,   16763,
    102282,   95226,       0,   65783,  105020,  126361,   99958,   78856,
     83372,   88446,  102086,   58749,  122812,  133679,  116801,   87603,
    147096,  139239,  119376,   75470,  122290,  111902,   88164,   76982,
     90050,   78414,   53690,   48565,   17695,   18572, 1566806,    9035,
     45390,   43363,   43217,   42190,   93872,   43157,   76233,   63880,
     79490,   79334,   60785,   49662,   72003,   74227,   56071,   60721,
     64682,  116148,  124334,   79158,   52843,   64838,  310260,   35476  },
  {16941141, 8330863, 8343560, 8523332,10250116,10544136, 9512804, 9187718,
   10372887,11194870,       0,10939756,13878557,10776800,10617675,15673123,
   10096404, 9465384,11018623, 9229766, 9245338,11028954, 9264736, 8321517,
   11143949,10947331,10722245, 8677036, 9482267,10981455,10926493, 9952914,
    9159072, 9465608,10342390, 9488532, 9822792,10856672,12356536, 7828215,
    7351119, 8731325, 9527330, 8259684, 8992879, 9530266, 8320425, 8715986,
    8356302, 7841705, 8117092, 7775844, 6933895, 9787468, 7225306, 9871928,
    9027883, 8799214,10589989, 8764586, 9264670, 9637947, 9041441, 8422721 }
};

static void
test_interrupts_real( void ) {
  int fd = open( "/proc/interrupts", O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "open(/proc/interrupts) failed (%i-%s), skipping test", errno, fd_io_strerror( errno ) ));
    return;
  }

  ulong cpu_cnt = fd_proc_interrupts_colwise( fd, per_cpu[0] );
  FD_TEST( 0==close( fd ) );
  FD_TEST( cpu_cnt>0UL );
  FD_LOG_NOTICE(( "Found %lu CPUs in /proc/interrupts", cpu_cnt ));
}

static void
test_interrupts_example( void ) {
  int memfd = memfd_create( "fake_proc_interrupts", 0 );
  FD_TEST( memfd>=0 );

  ulong write_sz;
  FD_TEST( 0==fd_io_write( memfd, example_interrupts, example_interrupts_sz, example_interrupts_sz, &write_sz ) );
  FD_TEST( write_sz==example_interrupts_sz );
  FD_TEST( 0==lseek( memfd, 0, SEEK_SET ) );

  ulong cpu_cnt = fd_proc_interrupts_colwise( memfd, per_cpu[0] );
  FD_TEST( 0==close( memfd ) );

  FD_TEST( cpu_cnt==64 );
  for( ulong cpu=0; cpu<cpu_cnt; cpu++ ) {
    FD_TEST( per_cpu[0][ cpu ]==example_interrupts_counters[ cpu ] );
  }
}

static void
test_softirqs_real( void ) {
  int fd = open( "/proc/softirqs", O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "open(/proc/softirqs) failed (%i-%s), skipping test", errno, fd_io_strerror( errno ) ));
    return;
  }

  ulong cpu_cnt = fd_proc_softirqs_sum( fd, per_cpu );
  FD_TEST( 0==close( fd ) );
  FD_TEST( cpu_cnt>0UL );
  FD_LOG_NOTICE(( "Found %lu CPUs in /proc/softirqs", cpu_cnt ));
}

static void
test_softirqs_example( void ) {
  int memfd = memfd_create( "fake_proc_softirqs", 0 );
  FD_TEST( memfd>=0 );

  ulong write_sz;
  FD_TEST( 0==fd_io_write( memfd, example_softirqs, example_softirqs_sz, example_softirqs_sz, &write_sz ) );
  FD_TEST( write_sz==example_softirqs_sz );
  FD_TEST( 0==lseek( memfd, 0, SEEK_SET ) );

  ulong cpu_cnt = fd_proc_softirqs_sum( memfd, per_cpu );
  FD_TEST( 0==close( memfd ) );

  FD_TEST( cpu_cnt==64 );
  for( ulong i=0UL; i<FD_METRICS_ENUM_SOFTIRQ_CNT; i++ ) {
    for( ulong c=0UL; c<cpu_cnt; c++ ) {
      FD_TEST( per_cpu[ i ][ c ]==example_softirqs_counters[ i ][ c ] );
    }
  }
}

static void
havoc( fd_rng_t * rng ) {
  for( ulong i=0UL; i<3UL; i++ ) for( ulong j=0UL; j<FD_TILE_MAX; j++ ) per_cpu[ i ][ j ] = fd_rng_ulong( rng );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  havoc( rng );
  test_interrupts_real();
  havoc( rng );
  test_interrupts_example();
  havoc( rng );
  test_softirqs_real();
  havoc( rng );
  test_softirqs_example();

  FD_LOG_NOTICE(( "pass" ));
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_halt();
  return 0;
}
