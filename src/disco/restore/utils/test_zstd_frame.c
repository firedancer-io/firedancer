#include "fd_zstd_frame.h"

#include "../../../util/fd_util.h"

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#define TEST_FRAME_MAX (4096UL)

static ulong
make_frame( uchar *       out,
            ulong         out_max,
            void const *  src,
            ulong         src_sz,
            int           content_size,
            int           checksum ) {
  ZSTD_CCtx * cctx = ZSTD_createCCtx();
  FD_TEST( cctx );
  FD_TEST( !ZSTD_isError( ZSTD_CCtx_setParameter( cctx, ZSTD_c_contentSizeFlag, content_size ) ) );
  FD_TEST( !ZSTD_isError( ZSTD_CCtx_setParameter( cctx, ZSTD_c_checksumFlag,    checksum     ) ) );

  ulong frame_sz = ZSTD_compress2( cctx, out, out_max, src, src_sz );
  FD_TEST( !ZSTD_isError( frame_sz ) );
  FD_TEST( !ZSTD_isError( ZSTD_freeCCtx( cctx ) ) );
  return frame_sz;
}

static int
scan( void const * data,
      ulong        data_sz,
      ulong *      consumed ) {
  fd_zstd_frame_t frame[1];
  FD_TEST( fd_zstd_frame_new( frame )==frame );
  return fd_zstd_frame_advance( frame, data, data_sz, consumed );
}

static void
test_all_splits( uchar const * frame,
                 ulong         frame_sz ) {
  for( ulong split=0UL; split<=frame_sz; split++ ) {
    fd_zstd_frame_t scan_state[1];
    FD_TEST( fd_zstd_frame_new( scan_state )==scan_state );

    ulong consumed = ULONG_MAX;
    int rc = fd_zstd_frame_advance( scan_state, frame, split, &consumed );
    FD_TEST( consumed==split );
    if( split==frame_sz ) {
      FD_TEST( rc==FD_ZSTD_FRAME_END );
      continue;
    }

    FD_TEST( rc==FD_ZSTD_FRAME_MORE );
    consumed = ULONG_MAX;
    rc = fd_zstd_frame_advance( scan_state, frame+split, frame_sz-split, &consumed );
    FD_TEST( rc==FD_ZSTD_FRAME_END );
    FD_TEST( consumed==frame_sz-split );
  }
}

static void
test_one_byte_fragments( uchar const * frame,
                         ulong         frame_sz ) {
  fd_zstd_frame_t scan_state[1];
  FD_TEST( fd_zstd_frame_new( scan_state )==scan_state );

  for( ulong off=0UL; off<frame_sz; off++ ) {
    ulong consumed = ULONG_MAX;
    int rc = fd_zstd_frame_advance( scan_state, frame+off, 1UL, &consumed );
    FD_TEST( consumed==1UL );
    FD_TEST( rc==(off+1UL==frame_sz ? FD_ZSTD_FRAME_END : FD_ZSTD_FRAME_MORE) );
  }
}

static void
test_valid_frame( uchar const * frame,
                  ulong         frame_sz ) {
  ulong oracle_sz = ZSTD_findFrameCompressedSize( frame, frame_sz );
  FD_TEST( !ZSTD_isError( oracle_sz ) );
  FD_TEST( oracle_sz==frame_sz );

  test_all_splits        ( frame, frame_sz );
  test_one_byte_fragments( frame, frame_sz );
}

static void
store_uint_le( uchar * dst,
               uint    value ) {
  dst[0] = (uchar)(value     );
  dst[1] = (uchar)(value>> 8);
  dst[2] = (uchar)(value>>16);
  dst[3] = (uchar)(value>>24);
}

static void
store_uint3_le( uchar * dst,
                uint    value ) {
  dst[0] = (uchar)(value     );
  dst[1] = (uchar)(value>> 8);
  dst[2] = (uchar)(value>>16);
}

static void
test_standard_frames( void ) {
  static uchar const payload[] =
    "Firedancer scans one physical Zstandard frame at a time.";

  uchar normal  [ TEST_FRAME_MAX ];
  uchar unknown [ TEST_FRAME_MAX ];
  uchar checksum[ TEST_FRAME_MAX ];
  uchar empty   [ TEST_FRAME_MAX ];

  ulong normal_sz   = make_frame( normal,   sizeof(normal),   payload, sizeof(payload)-1UL, 1, 0 );
  ulong unknown_sz  = make_frame( unknown,  sizeof(unknown),  payload, sizeof(payload)-1UL, 0, 0 );
  ulong checksum_sz = make_frame( checksum, sizeof(checksum), payload, sizeof(payload)-1UL, 1, 1 );
  ulong empty_sz    = make_frame( empty,    sizeof(empty),    payload, 0UL,                1, 0 );

  ZSTD_frameHeader hdr[1];
  FD_TEST( !ZSTD_getFrameHeader( hdr, unknown, unknown_sz ) );
  FD_TEST( hdr->frameContentSize==ZSTD_CONTENTSIZE_UNKNOWN );
  FD_TEST( !ZSTD_getFrameHeader( hdr, checksum, checksum_sz ) );
  FD_TEST( hdr->checksumFlag==1U );
  FD_TEST( !ZSTD_getFrameHeader( hdr, empty, empty_sz ) );
  FD_TEST( hdr->frameContentSize==0UL );

  test_valid_frame( normal,   normal_sz   );
  test_valid_frame( unknown,  unknown_sz  );
  test_valid_frame( checksum, checksum_sz );
  test_valid_frame( empty,    empty_sz    );

  uchar multi[] = {
    0x28U, 0xb5U, 0x2fU, 0xfdU, 0U, 0U, /* unknown size, 1 KiB window */
    0x10U, 0U, 0U, 'a', 'b',             /* non-last raw block, size 2 */
    0x19U, 0U, 0U, 'c', 'd', 'e'         /* last raw block, size 3 */
  };
  test_valid_frame( multi, sizeof(multi) );

  uchar rle[] = {
    0x28U, 0xb5U, 0x2fU, 0xfdU, 0U, 0U, /* unknown size, 1 KiB window */
    0x83U, 0U, 0U, 'z'                   /* last RLE block, size 16 */
  };
  uchar rle_out[16];
  FD_TEST( ZSTD_decompress( rle_out, sizeof(rle_out), rle, sizeof(rle) )==sizeof(rle_out) );
  for( ulong i=0UL; i<sizeof(rle_out); i++ ) FD_TEST( rle_out[i]=='z' );
  test_valid_frame( rle, sizeof(rle) );

  uchar stream[ 2UL*TEST_FRAME_MAX+3UL ];
  fd_memcpy( stream,           normal,  normal_sz  );
  fd_memcpy( stream+normal_sz, unknown, unknown_sz );
  stream[ normal_sz+unknown_sz     ] = 0xa5U;
  stream[ normal_sz+unknown_sz+1UL ] = 0x5aU;
  stream[ normal_sz+unknown_sz+2UL ] = 0xffU;

  ulong consumed = ULONG_MAX;
  int rc = scan( stream, normal_sz+unknown_sz+3UL, &consumed );
  FD_TEST( rc==FD_ZSTD_FRAME_END );
  FD_TEST( consumed==normal_sz );

  rc = scan( stream+consumed, unknown_sz+3UL, &consumed );
  FD_TEST( rc==FD_ZSTD_FRAME_END );
  FD_TEST( consumed==unknown_sz );
}

static void
test_skippable_frames( void ) {
  uchar frame[ 8UL+13UL+3UL ];
  store_uint_le( frame,     0x184d2a5aU );
  store_uint_le( frame+4UL, 13U          );
  for( ulong i=0UL; i<13UL; i++ ) frame[ 8UL+i ] = (uchar)(17UL*i);
  fd_memset( frame+21UL, 0xee, 3UL );

  ulong consumed = ULONG_MAX;
  int rc = scan( frame, sizeof(frame), &consumed );
  FD_TEST( rc==FD_ZSTD_FRAME_END );
  FD_TEST( consumed==21UL );
  test_valid_frame( frame, 21UL );

  uchar empty[ 8UL+1UL ];
  store_uint_le( empty,     0x184d2a50U );
  store_uint_le( empty+4UL, 0U          );
  empty[8] = 0xeeU;
  rc = scan( empty, sizeof(empty), &consumed );
  FD_TEST( rc==FD_ZSTD_FRAME_END );
  FD_TEST( consumed==8UL );
}

static void
test_invalid_frames( void ) {
  uchar invalid_magic[8] = { 0 };
  ulong consumed = ULONG_MAX;
  int rc = scan( invalid_magic, sizeof(invalid_magic), &consumed );
  FD_TEST( rc==FD_ZSTD_FRAME_ERR );
  FD_TEST( consumed<=sizeof(invalid_magic) );

  static uchar const payload[] = "oversized block";
  uchar valid[ TEST_FRAME_MAX ];
  ulong valid_sz = make_frame( valid, sizeof(valid), payload, sizeof(payload)-1UL, 1, 0 );

  ZSTD_frameHeader hdr[1];
  FD_TEST( !ZSTD_getFrameHeader( hdr, valid, valid_sz ) );

  uchar reserved[ TEST_FRAME_MAX ];
  fd_memcpy( reserved, valid, hdr->headerSize );
  store_uint3_le( reserved+hdr->headerSize, 7U ); /* last block, reserved type */
  rc = scan( reserved, hdr->headerSize+3UL, &consumed );
  FD_TEST( rc==FD_ZSTD_FRAME_ERR );

  uchar oversized[ TEST_FRAME_MAX ];
  fd_memcpy( oversized, valid, hdr->headerSize );
  uint block_header = ((hdr->blockSizeMax+1U)<<3) | 1U;
  store_uint3_le( oversized+hdr->headerSize, block_header );
  rc = scan( oversized, hdr->headerSize+3UL, &consumed );
  FD_TEST( rc==FD_ZSTD_FRAME_ERR );

  rc = scan( valid, 3UL, &consumed );
  FD_TEST( rc==FD_ZSTD_FRAME_MORE );
  FD_TEST( consumed==3UL );
}

static ulong
make_rle_frame( uchar * out,
                uint    block_sz ) {
  store_uint_le( out, 0xfd2fb528U );
  out[4] = 0U;    /* unknown content size */
  out[5] = 0x38U; /* 128 KiB window */
  store_uint3_le( out+6UL, (block_sz<<3) | 3U );
  out[9] = 'z';
  return 10UL;
}

static void
test_rle_block_bounds( void ) {
  uchar frame[10];

  ulong frame_sz = make_rle_frame( frame, 0U );
  test_valid_frame( frame, frame_sz );

  frame_sz = make_rle_frame( frame, 131072U );
  test_valid_frame( frame, frame_sz );

  make_rle_frame( frame, 131073U );
  ulong consumed = ULONG_MAX;
  FD_TEST( scan( frame, sizeof(frame), &consumed )==FD_ZSTD_FRAME_ERR );
  FD_TEST( consumed==9UL );
}

static void
test_terminal_and_zero_input( void ) {
  static uchar const payload[] = "terminal states";
  uchar frame[ TEST_FRAME_MAX ];
  ulong frame_sz = make_frame( frame, sizeof(frame), payload, sizeof(payload)-1UL, 1, 0 );

  fd_zstd_frame_t scanner[1];
  FD_TEST( fd_zstd_frame_new( scanner )==scanner );

  ulong consumed = ULONG_MAX;
  FD_TEST( fd_zstd_frame_advance( scanner, frame, frame_sz, &consumed )==FD_ZSTD_FRAME_END );
  FD_TEST( consumed==frame_sz );
  consumed = ULONG_MAX;
  FD_TEST( fd_zstd_frame_advance( scanner, frame, frame_sz, &consumed )==FD_ZSTD_FRAME_END );
  FD_TEST( !consumed );

  uchar invalid_magic[8] = { 0 };
  FD_TEST( fd_zstd_frame_new( scanner )==scanner );
  FD_TEST( fd_zstd_frame_advance( scanner, invalid_magic, sizeof(invalid_magic), &consumed )==FD_ZSTD_FRAME_ERR );
  consumed = ULONG_MAX;
  FD_TEST( fd_zstd_frame_advance( scanner, frame, frame_sz, &consumed )==FD_ZSTD_FRAME_ERR );
  FD_TEST( !consumed );

  FD_TEST( fd_zstd_frame_new( scanner )==scanner );
  FD_TEST( fd_zstd_frame_advance( scanner, frame, 3UL, &consumed )==FD_ZSTD_FRAME_MORE );
  FD_TEST( consumed==3UL );
  consumed = ULONG_MAX;
  FD_TEST( fd_zstd_frame_advance( scanner, frame+3UL, 0UL, &consumed )==FD_ZSTD_FRAME_MORE );
  FD_TEST( !consumed );
  FD_TEST( fd_zstd_frame_advance( scanner, frame+3UL, frame_sz-3UL, &consumed )==FD_ZSTD_FRAME_END );
  FD_TEST( consumed==frame_sz-3UL );

  uchar multi[] = {
    0x28U, 0xb5U, 0x2fU, 0xfdU, 0U, 0U,
    0x10U, 0U, 0U, 'a', 'b',
    0x19U, 0U, 0U, 'c', 'd', 'e'
  };
  FD_TEST( fd_zstd_frame_new( scanner )==scanner );
  FD_TEST( fd_zstd_frame_advance( scanner, multi, 10UL, &consumed )==FD_ZSTD_FRAME_MORE );
  FD_TEST( consumed==10UL );
  consumed = ULONG_MAX;
  FD_TEST( fd_zstd_frame_advance( scanner, multi+10UL, 0UL, &consumed )==FD_ZSTD_FRAME_MORE );
  FD_TEST( !consumed );
  FD_TEST( fd_zstd_frame_advance( scanner, multi+10UL, sizeof(multi)-10UL, &consumed )==FD_ZSTD_FRAME_END );
  FD_TEST( consumed==sizeof(multi)-10UL );
}

static void
test_checksummed_concatenation( void ) {
  static uchar const payload[] = "checksum boundary";
  uchar first [ TEST_FRAME_MAX ];
  uchar second[ TEST_FRAME_MAX ];
  uchar stream[ 2UL*TEST_FRAME_MAX ];

  ulong first_sz  = make_frame( first,  sizeof(first),  payload, sizeof(payload)-1UL, 1, 1 );
  ulong second_sz = make_frame( second, sizeof(second), payload, sizeof(payload)-1UL, 1, 0 );
  fd_memcpy( stream,          first,  first_sz  );
  fd_memcpy( stream+first_sz, second, second_sz );

  ulong consumed = ULONG_MAX;
  FD_TEST( scan( stream, first_sz+second_sz, &consumed )==FD_ZSTD_FRAME_END );
  FD_TEST( consumed==first_sz );
  FD_TEST( scan( stream+consumed, second_sz, &consumed )==FD_ZSTD_FRAME_END );
  FD_TEST( consumed==second_sz );

  stream[ first_sz-1UL ] ^= 1U; /* Scanner locates but does not validate the checksum */
  FD_TEST( scan( stream, first_sz+second_sz, &consumed )==FD_ZSTD_FRAME_END );
  FD_TEST( consumed==first_sz );
}

static void
test_incomplete_header_fragmentation_consistency( void ) {
  uchar input[2] = { 0 };
  ulong whole_consumed = ULONG_MAX;
  int whole_rc = scan( input, sizeof(input), &whole_consumed );
  FD_TEST( whole_consumed<=sizeof(input) );

  fd_zstd_frame_t scanner[1];
  FD_TEST( fd_zstd_frame_new( scanner )==scanner );
  int fragmented_rc = FD_ZSTD_FRAME_MORE;
  for( ulong i=0UL; i<sizeof(input); i++ ) {
    ulong consumed = ULONG_MAX;
    fragmented_rc = fd_zstd_frame_advance( scanner, input+i, 1UL, &consumed );
    FD_TEST( consumed<=1UL );
    if( fragmented_rc!=FD_ZSTD_FRAME_MORE ) break;
  }
  FD_TEST( fragmented_rc==whole_rc );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_standard_frames();
  test_skippable_frames();
  test_invalid_frames();
  test_rle_block_bounds();
  test_terminal_and_zero_input();
  test_checksummed_concatenation();
  test_incomplete_header_fragmentation_consistency();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
