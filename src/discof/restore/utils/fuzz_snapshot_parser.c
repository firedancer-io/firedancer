#include "fd_ssparse.h"

#include "../../../util/fd_util.h"
#include "../../../util/archive/fd_tar.h"
#include "../../../util/sanitize/fd_fuzz.h"

#include <assert.h>
#include <stdlib.h>

#define MAX_ACC_VEC_CNT (64UL)

static void * parser_mem;

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set   ( 4 );
  fd_log_level_logfile_set( 4 );

  parser_mem = aligned_alloc( fd_ssparse_align(), fd_ssparse_footprint( 1024UL ) );
  assert( parser_mem );

  return 0;
}

static void
make_tar_hdr( uchar *      data,
              char const * name,
              ulong        name_sz,
              ulong        file_sz ) {
  fd_tar_meta_t * tar = (fd_tar_meta_t *)data;
  LLVMFuzzerMutate( data, sizeof(fd_tar_meta_t), sizeof(fd_tar_meta_t) );
  fd_memcpy( tar->magic, FD_TAR_MAGIC, 6UL );
  fd_memcpy( tar->name, name, name_sz );
  fd_tar_meta_set_size( tar, file_sz );
  tar->typeflag = FD_TAR_TYPE_REGULAR;
}

static ulong
add_snapshot_chunk( uchar *      data,
                    ulong *      offset,
                    ulong *      avail,
                    char const * name,
                    ulong        name_sz,
                    ulong        file_sz ) {
  /* tar header for manifest */
  if( FD_UNLIKELY( *avail<sizeof(fd_tar_meta_t)+file_sz ) ) return LLVMFuzzerMutate( data + *offset, *avail, *avail );

  make_tar_hdr( data + *offset, name, name_sz, file_sz );
  *offset = *offset + sizeof(fd_tar_meta_t);
  *avail  = *avail - sizeof(fd_tar_meta_t);

  LLVMFuzzerMutate( data + *offset, file_sz, file_sz );
  *offset = *offset + file_sz;
  *avail  = *avail - file_sz;

  /* skip padding */
  ulong padding = fd_ulong_align_up( *offset, 512UL ) - *offset;
  if( FD_UNLIKELY( *avail<padding ) ) return LLVMFuzzerMutate( data + *offset, *avail, *avail );
  LLVMFuzzerMutate( data+*offset, padding, padding );
  *offset = *offset + padding;
  *avail  = *avail - padding;

  return 0;
}

static ulong
make_version( uchar *    data,
              fd_rng_t * rng,
              ulong *    offset,
              ulong *    avail ) {
  /* make a version tar header */
  ulong file_sz = 5UL;
  uint wrong_version_size = fd_rng_uint_roll( rng, 2U );
  if( FD_UNLIKELY( wrong_version_size ) ) file_sz = 5UL + fd_rng_ulong_roll( rng, 5UL );

  if( *avail<sizeof(fd_tar_meta_t)+file_sz ) return LLVMFuzzerMutate( data+*offset, *avail, *avail );
  make_tar_hdr( data+*offset, "version", 8UL, file_sz );
  *offset += sizeof(fd_tar_meta_t);
  *avail  -= sizeof(fd_tar_meta_t);

  uint random_version = fd_rng_uint_roll( rng, 2U );

  if( FD_LIKELY( random_version ) ) {
    LLVMFuzzerMutate( data+*offset, file_sz,  file_sz );
  } else {
    /* write version */
    fd_memcpy( data+*offset, "1.2.0", 5UL );
    *offset += file_sz;
    *avail  -= file_sz;
  }

  /* skip padding */
  ulong padding = fd_ulong_align_up( *offset, 512UL ) - *offset;
  if( FD_UNLIKELY( *avail<padding ) ) return LLVMFuzzerMutate( data+*offset, *avail, *avail );
  LLVMFuzzerMutate( data+*offset, padding, padding );
  *offset = *offset + padding;
  *avail  = *avail - padding;
  return 0;
}

static ulong
add_garbage( uchar * data,
             ulong * offset,
             ulong * avail,
             ulong   file_sz ) {
  ulong byte_to_mutate = fd_ulong_min( sizeof(fd_tar_meta_t)+file_sz, *avail );
  LLVMFuzzerMutate( data+*offset, byte_to_mutate, byte_to_mutate );
  *offset = *offset + byte_to_mutate;
  *avail  = *avail - byte_to_mutate;

  /* skip padding */
  ulong padding = fd_ulong_align_up( *offset, 512UL ) - *offset;
  if( FD_UNLIKELY( *avail<padding ) ) return LLVMFuzzerMutate( data + *offset, *avail, *avail );
  LLVMFuzzerMutate( data+*offset, padding, padding );
  *offset = *offset + padding;
  *avail  = *avail - padding;

  return 0;
}

#define NUM_SNAPSHOT_CHUNK_TYPES (6U)

#define VERSION           (0U)
#define STATUS_CACHE      (1U)
#define MANIFEST          (2U)
#define ACCOUNT           (3U)
#define STRUCTURED_RANDOM (4U)
#define GARBAGE           (5U)

ulong
LLVMFuzzerCustomMutator( uchar * data,
                         ulong   size,
                         ulong   max_size,
                         uint    seed ) {
  (void)size;
  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, seed, 0UL ) ) );
  ulong offset = 0UL;
  ulong avail  = max_size;

  /* create append vec mapping at front of input */
  ulong slots[ MAX_ACC_VEC_CNT ];
  ulong ids[ MAX_ACC_VEC_CNT ];
  ulong file_szs[ MAX_ACC_VEC_CNT ];
  ulong acc_vec_cnt = fd_rng_ulong_roll( rng, MAX_ACC_VEC_CNT );
  for( ulong i=0UL; i<acc_vec_cnt; i++ ) {
    file_szs[ i ] = fd_rng_ulong_roll( rng, 65536UL );
    slots[ i ]    = i;
    ids[ i ]      = i;
  }

  if( FD_UNLIKELY( avail<8UL+24UL*acc_vec_cnt ) ) return LLVMFuzzerMutate( data, avail, avail );
  *(ulong *)data = acc_vec_cnt;
  offset += 8UL;
  avail  -= 8UL;

  for( ulong i=0UL; i<acc_vec_cnt; i++ ) {
    *(ulong *)(data+offset)      = slots[ i ];
    *(ulong *)(data+offset+8UL)  = ids[ i ];
    *(ulong *)(data+offset+16UL) = file_szs[ i ];
    offset += 24UL;
    avail  -= 24UL;
  }

  /* pad to 512 bytes */
  ulong padding = fd_ulong_align_up( offset, 512UL ) - offset;
  if( FD_UNLIKELY( avail<padding ) ) return LLVMFuzzerMutate( data+offset, avail, avail );
  offset += padding;
  avail  -= padding;

  if( FD_UNLIKELY( avail<sizeof(fd_tar_meta_t) ) ) return LLVMFuzzerMutate( data, avail, avail );

  uint random_snapshot_chunks = fd_rng_uint_roll( rng, 2U );

  if( FD_LIKELY( random_snapshot_chunks ) ) {
    avail -= sizeof(fd_tar_meta_t)*2UL; /* reserve space for final zero tar frame and a valid tar frame */

    for(;;) {
      uint snapshot_chunk_type = fd_rng_uint_roll( rng, NUM_SNAPSHOT_CHUNK_TYPES );

      switch( snapshot_chunk_type ) {
        case VERSION: {
          ulong done = make_version( data, rng, &offset, &avail );
          if( FD_UNLIKELY( done ) ) goto end;
          break;
        }
        case MANIFEST: {
          /* tar header for manifest */
          ulong done = add_snapshot_chunk( data, &offset, &avail, "snapshots/123", 14UL, fd_rng_ulong_roll( rng, 16384UL ) );
          if( FD_UNLIKELY( done ) ) goto end;
          break;
        }
        case STATUS_CACHE: {
          ulong done = add_snapshot_chunk( data, &offset, &avail, "snapshots/status_cache", 23UL, fd_rng_ulong_roll( rng, 16384UL ) );
          if( FD_UNLIKELY( done ) ) goto end;
          break;
        }
        case ACCOUNT: {
          /* Add some account vecs */
          for( ulong i=0UL; i<acc_vec_cnt; i++ ) {
            if( FD_UNLIKELY( avail<sizeof(fd_tar_meta_t)+file_szs[ i ] ) ) return LLVMFuzzerMutate( data+offset, avail, avail );

            char name[ 100UL ];
            ulong name_sz;
            FD_TEST( fd_cstr_printf_check( name, 256UL, &name_sz, "accounts/%lu.%lu", slots[ i ], ids[ i ] ) );
            uint wrong_file_sz = fd_rng_uint_roll( rng, 2U );
            ulong file_sz = file_szs[ i ];
            if( FD_UNLIKELY( wrong_file_sz ) ) file_sz += fd_rng_ulong_roll( rng, 4096UL );
            ulong done = add_snapshot_chunk( data, &offset, &avail, name, name_sz, file_sz );
            if( FD_UNLIKELY( done ) ) goto end;
          }
          break;
        }
        case STRUCTURED_RANDOM: {
          char name[ 100UL ];
          LLVMFuzzerMutate( (uchar *)name, 99UL, 99UL );
          name[99UL ] = '\0';
          ulong done = add_snapshot_chunk( data, &offset, &avail, name, sizeof(name), fd_rng_ulong_roll( rng, 4096UL ) );
          if( FD_UNLIKELY( done ) ) goto end;
          break;
        }
        case GARBAGE: {
          ulong done = add_garbage( data, &offset, &avail, fd_rng_ulong_roll( rng, 4096UL ) );
          if( FD_UNLIKELY( done ) ) goto end;
          break;
        }
        default:
          FD_LOG_ERR(( "unknown snapshot chunk type %u", snapshot_chunk_type ));
          break;
      }
    }
  } else {
    /* make a version tar header */
    ulong done = make_version( data, rng, &offset, &avail );
    if( FD_UNLIKELY( done ) ) goto end;

    /* status cache */
    ulong file_sz = fd_rng_ulong_roll( rng, 4096UL );
    done = add_snapshot_chunk( data, &offset, &avail, "snapshots/status_cache", 23UL, file_sz );
    if( FD_UNLIKELY( done ) ) goto end;

    /* manifest */
    file_sz = fd_rng_ulong_roll( rng, 16384UL );
    done = add_snapshot_chunk( data, &offset, &avail, "snapshots/123", 14UL, file_sz );
    if( FD_UNLIKELY( done ) ) goto end;

    /* Add some account vecs */
    for( ulong i=0UL; i<acc_vec_cnt; i++ ) {
      if( FD_UNLIKELY( avail<sizeof(fd_tar_meta_t)+file_szs[ i ] ) ) return LLVMFuzzerMutate( data+offset, avail, avail );

      char name[ 100UL ];
      ulong name_sz;
      FD_TEST( fd_cstr_printf_check( name, 256UL, &name_sz, "accounts/%lu.%lu", slots[ i ], ids[ i ] ) );
      uint wrong_file_sz = fd_rng_uint_roll( rng, 2U );
      ulong file_sz = file_szs[ i ];
      if( FD_UNLIKELY( wrong_file_sz ) ) file_sz += fd_rng_ulong_roll( rng, 4096UL );
      ulong done = add_snapshot_chunk( data, &offset, &avail, name, name_sz, file_sz );
      if( FD_UNLIKELY( done ) ) goto end;
    }

    uint include_garbage = fd_rng_uint_roll( rng, 2U );
    if( FD_LIKELY( include_garbage ) ) {
      add_garbage( data, &offset, &avail, fd_rng_ulong_roll( rng, 4096UL ) );
    }
  }

end:
  if( FD_LIKELY( random_snapshot_chunks ) ) avail += sizeof(fd_tar_meta_t)*2UL;
  /* zero tar frame */
  padding = 512UL;
  if( FD_UNLIKELY( avail<padding ) ) return LLVMFuzzerMutate( data+offset, avail, avail );
  fd_memset( data+offset, 0, padding );
  offset += padding;
  avail  -= padding;

  uint random_valid_tar_hdr = fd_rng_uint_roll( rng, 2U );
  if( FD_LIKELY( random_valid_tar_hdr ) ) {
    if( FD_UNLIKELY( avail<sizeof(fd_tar_meta_t) ) ) return LLVMFuzzerMutate( data+offset, avail, avail );
    make_tar_hdr( data+offset, "version", 8UL, 5UL );
    offset += sizeof(fd_tar_meta_t);
    avail  -= sizeof(fd_tar_meta_t);
  } else {
    /* zero tar frame */
    padding = 512UL;
    if( FD_UNLIKELY( avail<padding ) ) return LLVMFuzzerMutate( data+offset, avail, avail );
    fd_memset( data+offset, 0, padding );
    offset += padding;
    avail  -= padding;
  }


  return offset;
}

int
LLVMFuzzerTestOneInput( uchar const * const data,
                        ulong         const size ) {
  fd_ssparse_t * parser = fd_ssparse_new( parser_mem, 1024UL, 42UL );
  assert( parser );

  fd_ssparse_reset( parser );

  if( FD_UNLIKELY( size<sizeof(ulong) ) ) return -1;
  ulong acc_vec_cnt = *(ulong *)data;
  if( FD_UNLIKELY( acc_vec_cnt>MAX_ACC_VEC_CNT ) ) return -1;

  ulong offset_to_padding = 8UL + 24UL*acc_vec_cnt;
  if( FD_UNLIKELY( size<offset_to_padding ) ) return -1;

  ulong slots[ MAX_ACC_VEC_CNT ];
  ulong ids[ MAX_ACC_VEC_CNT ];
  ulong file_szs[ MAX_ACC_VEC_CNT ];
  for( ulong i=0UL; i<acc_vec_cnt; i++ ) {
    slots[ i ]    = *(ulong *)(data+8UL+24UL*i);
    ids[ i ]      = *(ulong *)(data+8UL+24UL*i+8UL);
    file_szs[ i ] = *(ulong *)(data+8UL+24UL*i+16UL);
  }

  if( FD_UNLIKELY( fd_ssparse_populate_acc_vec_map( parser, slots, ids, file_szs, acc_vec_cnt ) ) ) return -1;

  ulong offset_to_input = fd_ulong_align_up( offset_to_padding, 512UL );
  if( FD_UNLIKELY( size<offset_to_input ) ) return -1;

  /* FIXME split input in the future */
  fd_ssparse_advance_result_t result[1];
  uchar const * data_ptr = data + offset_to_input;
  ulong         data_sz  = size - offset_to_input;
  for (;;) {
    int res = fd_ssparse_advance( parser, data_ptr, data_sz, result );
    if( res==FD_SSPARSE_ADVANCE_DONE || res==FD_SSPARSE_ADVANCE_ERROR ) break;
    data_ptr += result->bytes_consumed;
    data_sz  -= result->bytes_consumed;
  }
  return 0;
}
