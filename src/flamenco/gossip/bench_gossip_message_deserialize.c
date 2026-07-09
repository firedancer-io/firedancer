#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>

#include "../../util/fd_util.h"
#include "fd_gossip_message.h"

extern int
gossip_agave_deserialize( uchar const * data,
                          ulong         len );

#define MAX_CORPUS_ENTRIES (65536UL)
#define MAX_CORPUS_BYTES   (MAX_CORPUS_ENTRIES*1232UL)

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * corpus_dir     = fd_env_strip_cmdline_cstr( &argc, &argv, "--corpus", NULL, "corpus/fuzz_gossip_message_deserialize" );
  char const * ser_corpus_dir = fd_env_strip_cmdline_cstr( &argc, &argv, "--ser-corpus", NULL, "corpus/fuzz_gossip_message_serialize" );
  ulong        reps           = fd_env_strip_cmdline_ulong( &argc, &argv, "--reps", NULL, 200UL );

  /* Load corpus into memory */

  uchar * corpus_data = malloc( MAX_CORPUS_BYTES );
  ulong * corpus_off  = malloc( MAX_CORPUS_ENTRIES * sizeof(ulong) ); /* offset into corpus_data */
  ulong * corpus_sz   = malloc( MAX_CORPUS_ENTRIES * sizeof(ulong) ); /* size of each entry */
  FD_TEST( corpus_data && corpus_off && corpus_sz );

  ulong corpus_cnt      = 0UL;
  ulong corpus_data_off = 0UL;

  DIR * dir = opendir( corpus_dir );
  if( FD_UNLIKELY( !dir ) ) FD_LOG_ERR(( "opendir(%s) failed", corpus_dir ));

  struct dirent * ent;
  while( (ent = readdir( dir )) ) {
    if( ent->d_name[0]=='.' ) continue;

    char path[ 4096 ];
    int n = snprintf( path, sizeof(path), "%s/%s", corpus_dir, ent->d_name );
    FD_TEST( n>0 && (ulong)n<sizeof(path) );

    struct stat st;
    if( stat( path, &st ) ) continue;
    if( !S_ISREG( st.st_mode ) ) continue;
    if( st.st_size>1232L || st.st_size<=0L ) continue;

    FD_TEST( corpus_cnt < MAX_CORPUS_ENTRIES );
    FD_TEST( corpus_data_off + (ulong)st.st_size <= MAX_CORPUS_BYTES );

    FILE * f = fopen( path, "rb" );
    FD_TEST( f );
    FD_TEST( fread( corpus_data + corpus_data_off, 1, (ulong)st.st_size, f ) == (ulong)st.st_size );
    fclose( f );

    corpus_off[ corpus_cnt ] = corpus_data_off;
    corpus_sz [ corpus_cnt ] = (ulong)st.st_size;
    corpus_data_off += (ulong)st.st_size;
    corpus_cnt++;
  }
  closedir( dir );

  FD_LOG_NOTICE(( "Loaded %lu corpus entries (%lu bytes total)", corpus_cnt, corpus_data_off ));
  FD_TEST( corpus_cnt );

  fd_gossip_message_t * msg = malloc( sizeof(fd_gossip_message_t) );
  FD_TEST( msg );

  /* Warmup */

  for( ulong i=0UL; i<corpus_cnt; i++ ) {
    fd_gossip_message_deserialize( msg, corpus_data + corpus_off[ i ], corpus_sz[ i ] );
    gossip_agave_deserialize( corpus_data + corpus_off[ i ], corpus_sz[ i ] );
  }

  /* Benchmark Firedancer */

  long fd_t0 = fd_log_wallclock();
  for( ulong r=0UL; r<reps; r++ ) {
    for( ulong i=0UL; i<corpus_cnt; i++ ) {
      fd_gossip_message_deserialize( msg, corpus_data + corpus_off[ i ], corpus_sz[ i ] );
    }
  }
  long fd_t1 = fd_log_wallclock();

  /* Benchmark Agave */

  long agave_t0 = fd_log_wallclock();
  for( ulong r=0UL; r<reps; r++ ) {
    for( ulong i=0UL; i<corpus_cnt; i++ ) {
      gossip_agave_deserialize( corpus_data + corpus_off[ i ], corpus_sz[ i ] );
    }
  }
  long agave_t1 = fd_log_wallclock();

  ulong total_calls = reps * corpus_cnt;
  double fd_ns      = (double)(fd_t1 - fd_t0) / (double)total_calls;
  double agave_ns   = (double)(agave_t1 - agave_t0) / (double)total_calls;

  FD_LOG_NOTICE(( "=== DESERIALIZER ===" ));
  FD_LOG_NOTICE(( "reps=%lu  corpus=%lu  total_calls=%lu", reps, corpus_cnt, total_calls ));
  FD_LOG_NOTICE(( "fd:    %.1f ns/call  (%.3f s total)", fd_ns, (double)(fd_t1 - fd_t0) * 1e-9 ));
  FD_LOG_NOTICE(( "agave: %.1f ns/call  (%.3f s total)", agave_ns, (double)(agave_t1 - agave_t0) * 1e-9 ));
  FD_LOG_NOTICE(( "ratio: %.2fx", agave_ns / fd_ns ));

  free( msg );
  free( corpus_sz );
  free( corpus_off );
  free( corpus_data );

  /* ================================================================
     Serializer benchmark
     ================================================================ */

  /* Load serializer corpus — these should be valid gossip messages
     containing serializable value types. We deserialize them to
     extract fd_gossip_value_t structs, then benchmark serializing. */

#define MAX_SER_VALUES (65536UL)

  fd_gossip_value_t * ser_values = malloc( MAX_SER_VALUES * sizeof(fd_gossip_value_t) );
  FD_TEST( ser_values );
  ulong ser_cnt = 0UL;

  corpus_data = malloc( MAX_CORPUS_BYTES );
  FD_TEST( corpus_data );

  DIR * ser_dir = opendir( ser_corpus_dir );
  if( FD_UNLIKELY( !ser_dir ) ) {
    FD_LOG_WARNING(( "opendir(%s) failed, skipping serializer benchmark", ser_corpus_dir ));
    goto skip_ser;
  }

  fd_gossip_message_t * tmp_msg = malloc( sizeof(fd_gossip_message_t) );
  FD_TEST( tmp_msg );

  corpus_data_off = 0UL;
  while( (ent = readdir( ser_dir )) ) {
    if( ent->d_name[0]=='.' ) continue;

    char path[ 4096 ];
    int n = snprintf( path, sizeof(path), "%s/%s", ser_corpus_dir, ent->d_name );
    FD_TEST( n>0 && (ulong)n<sizeof(path) );

    struct stat st;
    if( stat( path, &st ) ) continue;
    if( !S_ISREG( st.st_mode ) ) continue;
    if( st.st_size>1232L || st.st_size<=0L ) continue;

    uchar file_buf[ 1232 ];
    FILE * f = fopen( path, "rb" );
    if( !f ) continue;
    ulong fsz = fread( file_buf, 1, (ulong)st.st_size, f );
    fclose( f );
    if( fsz!=(ulong)st.st_size ) continue;

    memset( tmp_msg, 0, sizeof(fd_gossip_message_t) );
    if( !fd_gossip_message_deserialize( tmp_msg, file_buf, fsz ) ) continue;

    /* Extract serializable values from Push / PullResponse messages */
    fd_gossip_value_t * vals     = NULL;
    ulong               vals_len = 0UL;
    if( tmp_msg->tag==FD_GOSSIP_MESSAGE_PUSH ) {
      vals     = tmp_msg->push->values;
      vals_len = tmp_msg->push->values_len;
    } else if( tmp_msg->tag==FD_GOSSIP_MESSAGE_PULL_RESPONSE ) {
      vals     = tmp_msg->pull_response->values;
      vals_len = tmp_msg->pull_response->values_len;
    }

    for( ulong i=0UL; i<vals_len && ser_cnt<MAX_SER_VALUES; i++ ) {
      uint t = vals[ i ].tag;
      if( t==FD_GOSSIP_VALUE_VOTE            ||
          t==FD_GOSSIP_VALUE_NODE_INSTANCE    ||
          t==FD_GOSSIP_VALUE_DUPLICATE_SHRED  ||
          t==FD_GOSSIP_VALUE_SNAPSHOT_HASHES  ||
          t==FD_GOSSIP_VALUE_CONTACT_INFO     ) {
        ser_values[ ser_cnt++ ] = vals[ i ];
      }
    }
  }
  closedir( ser_dir );
  free( tmp_msg );

  if( FD_UNLIKELY( !ser_cnt ) ) {
    FD_LOG_WARNING(( "No serializable values found in %s, skipping serializer benchmark", ser_corpus_dir ));
    goto skip_ser;
  }

  FD_LOG_NOTICE(( "Loaded %lu serializable values from %s", ser_cnt, ser_corpus_dir ));

  uchar ser_out[ 1232 ];

  /* Warmup */
  for( ulong i=0UL; i<ser_cnt; i++ ) {
    fd_gossip_value_serialize( &ser_values[ i ], ser_out, sizeof(ser_out) );
  }

  /* Benchmark serializer */
  long ser_t0 = fd_log_wallclock();
  for( ulong r=0UL; r<reps; r++ ) {
    for( ulong i=0UL; i<ser_cnt; i++ ) {
      fd_gossip_value_serialize( &ser_values[ i ], ser_out, sizeof(ser_out) );
    }
  }
  long ser_t1 = fd_log_wallclock();

  ulong  ser_total = reps * ser_cnt;
  double ser_ns    = (double)(ser_t1 - ser_t0) / (double)ser_total;

  FD_LOG_NOTICE(( "=== SERIALIZER ===" ));
  FD_LOG_NOTICE(( "reps=%lu  values=%lu  total_calls=%lu", reps, ser_cnt, ser_total ));
  FD_LOG_NOTICE(( "fd:    %.1f ns/call  (%.3f s total)", ser_ns, (double)(ser_t1 - ser_t0) * 1e-9 ));

skip_ser:
  free( ser_values );
  free( corpus_data );

  fd_halt();
  return 0;
}
