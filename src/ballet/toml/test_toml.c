#include "fd_toml.h"
#include "../../util/fd_util.h"
#include "../json/cJSON.h"

/* test_toml.c executes builtin unit tests as well as externally
   supplied files.  If no arguments are given, it executes a hardcoded
   list of tests. */

#if !FD_HAS_HOSTED
#error "test_toml.c requires FD_HAS_HOSTED"
#endif

#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

static uchar file_buf[ 16384 ];

/* TOML<=>JSON match tests ********************************************/

static regex_t match_localtime;

/* The valid encodings in src/ballet/toml/tests each come with a .json
   fixture that specifies how the encoding should look like in JSON.
   This JSON format is quite bizarre (has arbitrary "type" tags on
   tables but not on arrays, encodes bools as strings, ...). */

static void
compare_value( fd_pod_info_t const * info,
               cJSON const *         obj );

static void
compare_object( uchar const * pod,
                cJSON const * obj ) {
  FD_TEST( obj->type==cJSON_Object );

  ulong json_cnt = (ulong)cJSON_GetArraySize( obj );
  ulong toml_cnt = fd_pod_cnt( pod );
  if( FD_UNLIKELY( json_cnt!=toml_cnt ) )
    FD_LOG_ERR(( "expected %lu keys in object, got %lu", json_cnt, toml_cnt ));

  for( cJSON * json_ele = obj->child; json_ele; json_ele = json_ele->next ) {
    fd_pod_info_t info;
    if( FD_UNLIKELY( fd_pod_query( pod, json_ele->string, &info ) ) ) {
      FD_LOG_ERR(( "key %s not found in toml", json_ele->string ));
      continue;
    }
    compare_value( &info, json_ele );
  }
}

static void
compare_array( uchar const * pod,
               cJSON const * obj ) {
  FD_TEST( obj->type==cJSON_Array );

  ulong json_cnt = (ulong)cJSON_GetArraySize( obj );
  ulong toml_cnt = fd_pod_cnt( pod );
  if( FD_UNLIKELY( json_cnt!=toml_cnt ) )
    FD_LOG_ERR(( "expected %lu keys in object, got %lu", json_cnt, toml_cnt ));

  ulong i=0UL;
  for( cJSON * json_ele = obj->child; json_ele; json_ele = json_ele->next ) {
    char path[ 22 ];
    fd_cstr_fini( fd_cstr_append_ulong_as_text( fd_cstr_init( path ), 0, 0, i, fd_ulong_base10_dig_cnt( i ) ) );
    fd_pod_info_t info;
    if( FD_UNLIKELY( fd_pod_query( pod, path, &info ) ) ) {
      FD_LOG_ERR(( "key %s not found in toml", path ));
      continue;
    }
    compare_value( &info, json_ele );
    i++;
  }
}

static void
compare_bool( int toml_val,
              int json_val ) {
  (void)toml_val; (void)json_val;
  /* TODO */
}

static void
compare_value( fd_pod_info_t const * info,
               cJSON const *         obj ) {

  char pod_val_type[ FD_POD_VAL_TYPE_CSTR_MAX ];

  if( obj->type == cJSON_Array ) {
    if( FD_UNLIKELY( info->val_type != FD_POD_VAL_TYPE_SUBPOD ) )
      FD_LOG_ERR(( "expected array (subpod), got %s", fd_pod_val_type_to_cstr( info->val_type, pod_val_type ) ));
    compare_array( info->val, obj );
    return;
  }

  if( obj->type != cJSON_Object ) FD_LOG_ERR(( "Unexpected JSON node: %d", obj->type ));

  char const * type_cstr = cJSON_GetStringValue( cJSON_GetObjectItem( obj, "type"  ) );
  cJSON *      json_val  =                       cJSON_GetObjectItem( obj, "value" );

  if( type_cstr == NULL ) {
    /* Why are objects not externally tagged as such? sigh ... */
    if( FD_UNLIKELY( info->val_type != FD_POD_VAL_TYPE_SUBPOD ) )
      FD_LOG_ERR(( "expected object (subpod), got %s", fd_pod_val_type_to_cstr( info->val_type, pod_val_type ) ));
    compare_object( info->val, obj );
  } else if( 0==strcmp( type_cstr, "integer" ) ) {
    if( FD_UNLIKELY( info->val_type != FD_POD_VAL_TYPE_ULONG ) )
      FD_LOG_ERR(( "expected ulong, got %s", fd_pod_val_type_to_cstr( info->val_type, pod_val_type ) ));
    char const * json_num_cstr = cJSON_GetStringValue( json_val );
    FD_TEST( json_num_cstr );
    long json_num = fd_cstr_to_long( json_num_cstr );
    ulong toml_num_2c; fd_ulong_svw_dec( (uchar const *)info->val, &toml_num_2c );
    long toml_num = (long)toml_num_2c;
    if( FD_UNLIKELY( json_num != toml_num ) ) {
      FD_LOG_ERR(( "expected integer %ld, got %ld", json_num, toml_num ));
    }
  } else if( 0==strcmp( type_cstr, "datetime" ) ) {
    if( FD_UNLIKELY( info->val_type != FD_POD_VAL_TYPE_ULONG ) )
      FD_LOG_ERR(( "expected ulong, got %s", fd_pod_val_type_to_cstr( info->val_type, pod_val_type ) ));
    char const * json_cstr = cJSON_GetStringValue( json_val );
    FD_TEST( json_cstr );
    FD_LOG_WARNING(( "datetime: %s", json_cstr ));
  } else if( 0==strcmp( type_cstr, "datetime-local" ) ) {

  } else if( 0==strcmp( type_cstr, "date-local" ) ) {
    /* TODO */
  } else if( 0==strcmp( type_cstr, "time-local" ) ) {
    if( FD_UNLIKELY( info->val_type != FD_POD_VAL_TYPE_ULONG ) )
      FD_LOG_ERR(( "expected ulong, got %s", fd_pod_val_type_to_cstr( info->val_type, pod_val_type ) ));
    ulong toml_num; fd_ulong_svw_dec( (uchar const *)info->val, &toml_num );
    char const * json_cstr = cJSON_GetStringValue( json_val );
    FD_TEST( json_cstr );
    regmatch_t matches[3];
    FD_TEST( 0==regexec( &match_localtime, json_cstr, 3, matches, 0 ) );
    uint hour; uint min; uint sec;
    FD_TEST( 3==sscanf( json_cstr, "%u:%u:%u", &hour, &min, &sec ) );
    ulong wallclock = (ulong)1e9 * ((ulong)hour * 3600UL + (ulong)min * 60UL + (ulong)sec);
    if( matches[2].rm_so != -1 ) {
      char num_str[10]; fd_memset( num_str, '0', 9 ); num_str[9] = 0;
      char const * frac = json_cstr + matches[2].rm_so + 1;
      uint frac_len = (uint)(matches[2].rm_eo - matches[2].rm_so - 1);
           frac_len = fd_uint_min( frac_len, 9U );
      fd_memcpy( num_str, frac, frac_len );
      ulong frac_ns = fd_cstr_to_ulong( num_str );
      wallclock += frac_ns;
    }
    if( FD_UNLIKELY( wallclock != toml_num ) ) {
      FD_LOG_ERR(( "expected time %lu ns, got %lu ns (%s)", wallclock, toml_num, json_cstr ));
    }
  } else if( 0==strcmp( type_cstr, "float" ) ) {
    /* TODO */
  } else if( 0==strcmp( type_cstr, "string" ) ) {
    if( FD_UNLIKELY( info->val_type != FD_POD_VAL_TYPE_CSTR ) )
      FD_LOG_ERR(( "expected string (cstr), got %s", fd_pod_val_type_to_cstr( info->val_type, pod_val_type ) ));
    char const * toml_cstr = (char const *)info->val;
    ulong toml_cstr_len = info->val_sz - 1UL;
    char const * json_cstr = cJSON_GetStringValue( json_val );
    FD_TEST( json_cstr );
    ulong json_cstr_len = strlen( json_cstr );
    if( FD_UNLIKELY( json_cstr_len != toml_cstr_len ||
                     0!=memcmp( json_cstr, toml_cstr, json_cstr_len ) ) ) {
      FD_LOG_HEXDUMP_WARNING(( "JSON cstr", json_cstr, json_cstr_len ));
      FD_LOG_HEXDUMP_WARNING(( "TOML cstr", toml_cstr, toml_cstr_len ));
      FD_LOG_ERR(( "incorrect string" ));
    }
  } else if( 0==strcmp( type_cstr, "bool" ) ) {
    int bool_val = 0==strcmp( cJSON_GetStringValue( json_val ), "true" );
    if( FD_UNLIKELY( info->val_type != FD_POD_VAL_TYPE_INT ) )
      FD_LOG_ERR(( "expected bool, got %s", fd_pod_val_type_to_cstr( info->val_type, pod_val_type ) ));
    compare_bool( FD_LOAD( int, info->val ), bool_val );
  } else {
    FD_LOG_ERR(( "unexpected JSON type %s", type_cstr ));
  }
}

static void
validate_against_json( char *  name,
                       uchar * pod,
                       int     dir_fd ) {
  ulong name_len = strlen( name );
  if( name_len<5 ) return;
  memcpy( name + name_len - 4, "json", 4 );

  int toml_fd = openat( dir_fd, name, O_RDONLY );
  FD_TEST( toml_fd>=0 );

  struct stat st;
  FD_TEST( 0==fstat( toml_fd, &st ) );
  FD_TEST( st.st_size <= (long)sizeof(file_buf) );

  long read_res = read( toml_fd, file_buf, (ulong)st.st_size );
  FD_TEST( read_res==st.st_size );
  FD_TEST( 0==close( toml_fd ) );

  cJSON * obj = cJSON_Parse( (char const *)file_buf );
  FD_TEST( obj );
  FD_TEST( obj->type == cJSON_Object );
  compare_object( pod, obj );
  cJSON_Delete( obj );
  memcpy( name + name_len - 4, "toml", 4 );
}

static void
run_test( char * test_name,
          int    is_invalid,
          int    dir_fd ) {
  char * nl = strchr( test_name, '\n' );
  if( nl ) *nl = 0;
  if( FD_UNLIKELY( !test_name[0] ) ) return;

  int toml_fd = openat( dir_fd, test_name, O_RDONLY );
  FD_TEST( toml_fd>=0 );

  struct stat st;
  FD_TEST( 0==fstat( toml_fd, &st ) );
  FD_TEST( st.st_size <= (long)sizeof(file_buf) );

  long read_res = read( toml_fd, file_buf, (ulong)st.st_size );
  FD_TEST( read_res==st.st_size );
  FD_TEST( 0==close( toml_fd ) );

  static uchar pod_mem[ 4096 ];
  uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );

  FD_LOG_DEBUG(( "Parsing %s", test_name ));
  uchar scratch[128];
  long res = fd_toml_parse( file_buf, (ulong)st.st_size, pod, scratch, sizeof(scratch) );
  if( is_invalid ) {
    if( FD_UNLIKELY( res==FD_TOML_SUCCESS ) ) {
      FD_LOG_ERR(( "%s: expected failure, got success", test_name ));
    }
  } else {
    if( FD_UNLIKELY( res!=FD_TOML_SUCCESS ) ) {
      FD_LOG_ERR(( "%s: expected success, got failure (res=%ld)", test_name, res ));
    }
    validate_against_json( test_name, pod, dir_fd );
  }

  fd_pod_delete( fd_pod_leave( pod ) );
  FD_LOG_INFO(( "%s: ok", test_name ));
}

static int
usage( void ) {
  FD_LOG_ERR(( "Usage: test_toml test1=ok test2=fail" ));
  return EXIT_FAILURE;
}

FD_IMPORT_CSTR( hardcoded_test_list, "src/ballet/toml/tests/fd_toml_tests.txt" );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_log_level_flush_set( 9 );  /* disable flushing */

  FD_TEST( 0==regcomp( &match_localtime, "^([[:digit:]]{2}:[[:digit:]]{2}:[[:digit:]]{2})(\\.[[:digit:]]+)?", REG_EXTENDED ) );

  ulong exec_cnt = 0UL;
  for( int arg=1; arg<argc; arg++ ) {
    if( 0!=strncmp( argv[arg], "--", 2 ) ) {
      char * eq = strchr( argv[arg], '=' );
      if( FD_UNLIKELY( !eq || !eq[0] ) ) return usage();

      *eq = 0;
      char const * val = eq+1;
      if( 0==strcmp( val, "ok" ) ) {
        run_test( argv[arg], 0, AT_FDCWD );
      } else if( 0==strcmp( val, "fail" ) ) {
        run_test( argv[arg], 1, AT_FDCWD );
      } else {
        return usage();
      }

      exec_cnt++;
    }
  }

  if( exec_cnt ) return 0;

  FILE * list_file = fmemopen( (void *)hardcoded_test_list, hardcoded_test_list_sz, "r" );
  FD_TEST( list_file );

  int dir_fd = open( "src/ballet/toml/tests", O_DIRECTORY );
  FD_TEST( dir_fd>=0 );

  static char test_name[ 4096 ];
  while( FD_LIKELY( fgets( test_name, 4096, list_file ) ) ) {
    int is_invalid = (0==strncmp( test_name, "invalid", 7 ));
    run_test( test_name, is_invalid, dir_fd );
  }
  FD_TEST( 0==ferror( list_file ) );
  FD_TEST( 0==fclose( list_file ) );

  FD_TEST( 0==close ( dir_fd    ) );

  regfree( &match_localtime );
  fd_halt();
  return 0;
}
