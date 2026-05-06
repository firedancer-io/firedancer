#include "fd_ssparse.h"

#include "../../../util/fd_util.h"
#include "../../../util/archive/fd_tar.h"
#include "../../../flamenco/runtime/fd_runtime_const.h"
#include "../../../flamenco/runtime/fd_system_ids_pp.h"

#include <stdlib.h>

static uchar tar_buf[ 65536 ];

static void
write_tar_header( uchar *      buf,
                  char const * name,
                  ulong        file_sz ) {
  fd_tar_meta_t * hdr = (fd_tar_meta_t *)buf;
  FD_TEST( fd_tar_meta_init_file_default( hdr, name, file_sz, 1700000000L/*~current epoch time*/ * 1000000000L/*second to ns*/ ) );
}

static void
write_tar_header_typed( uchar *      buf,
                        char const * name,
                        ulong        file_sz,
                        char         typeflag ) {
  write_tar_header( buf, name, file_sz );
  fd_tar_meta_t * hdr = (fd_tar_meta_t *)buf;
  hdr->typeflag = typeflag;
  /* Recompute checksum after modifying typeflag. */
  fd_memset( hdr->chksum, ' ', sizeof(hdr->chksum) );
  ulong checksum = 0;
  for( ulong i=0; i<512UL; i++ ) checksum += buf[i];
  fd_tar_set_octal( hdr->chksum, sizeof(hdr->chksum), checksum );
}

static ulong
append_tar_entry( uchar *       buf,
                  ulong         buf_sz,
                  ulong         off,
                  char const *  name,
                  uchar const * content,
                  ulong         content_sz ) {
  FD_TEST( off + 512UL + fd_ulong_align_up( content_sz, 512UL ) <= buf_sz );
  write_tar_header( buf+off, name, content_sz );
  off += 512UL;
  if( content_sz ) {
    fd_memcpy( buf+off, content, content_sz );
    ulong padded = fd_ulong_align_up( content_sz, 512UL );
    fd_memset( buf+off+content_sz, 0, padded-content_sz );
    off += padded;
  }
  return off;
}

static ulong
append_eof( uchar * buf,
            ulong   buf_sz,
            ulong   off ) {
  FD_TEST( off + 1024UL <= buf_sz );
  fd_memset( buf+off, 0, 1024UL );
  return off + 1024UL;
}

static int
feed_all( fd_ssparse_t * parser,
          uchar const *  data,
          ulong          data_sz ) {
  int last_result = FD_SSPARSE_ADVANCE_AGAIN;
  ulong zero_progress = 0UL;
  while( data_sz>0UL ) {
    fd_ssparse_advance_result_t result[1];
    int res = fd_ssparse_advance( parser, data, data_sz, result );
    if( res==FD_SSPARSE_ADVANCE_DONE || res==FD_SSPARSE_ADVANCE_ERROR ) return res;
    FD_TEST( result->bytes_consumed<=data_sz );
    if( FD_UNLIKELY( result->bytes_consumed==0UL ) ) {
      FD_TEST( ++zero_progress<1024UL ); /* detect stuck parser */
    } else {
      zero_progress = 0UL;
    }
    data    += result->bytes_consumed;
    data_sz -= result->bytes_consumed;
    if( res!=FD_SSPARSE_ADVANCE_AGAIN ) last_result = res;
  }
  return last_result;
}

static int
feed_bytewise( fd_ssparse_t * parser,
               uchar const *  data,
               ulong          data_sz ) {
  int last_result = FD_SSPARSE_ADVANCE_AGAIN;
  ulong zero_progress = 0UL;
  while( data_sz>0UL ) {
    fd_ssparse_advance_result_t result[1];
    int res = fd_ssparse_advance( parser, data, 1UL, result );
    if( res==FD_SSPARSE_ADVANCE_DONE || res==FD_SSPARSE_ADVANCE_ERROR ) return res;
    ulong consumed = result->bytes_consumed;
    FD_TEST( consumed<=1UL );
    if( FD_UNLIKELY( consumed==0UL ) ) {
      FD_TEST( ++zero_progress<1024UL ); /* detect stuck parser */
    } else {
      zero_progress = 0UL;
      data    += consumed;
      data_sz -= consumed;
    }
    if( res!=FD_SSPARSE_ADVANCE_AGAIN ) last_result = res;
  }
  return last_result;
}

static ulong
build_minimal_snapshot( uchar * buf,
                        ulong   buf_sz,
                        int     include_eof ) {
  ulong off = 0UL;
  off = append_tar_entry( buf, buf_sz, off, "version",                (uchar const *)"1.2.0",    5UL );
  off = append_tar_entry( buf, buf_sz, off, "snapshots/100",          (uchar const *)"\xAB\xAB", 2UL );
  off = append_tar_entry( buf, buf_sz, off, "snapshots/status_cache", (uchar const *)"\xCD\xCD", 2UL );
  if( include_eof ) off = append_eof( buf, buf_sz, off );
  return off;
}

static void
build_account_header( uchar * hdr,
                      ulong   data_len,
                      int     executable ) {
  /* Account header layout (136 bytes total):
       0: lamports      (8)
       8: data_len      (8)
      16: pubkey        (32)
      48: lamports      (8)   -- duplicate, used by runtime
      56: rent_epoch    (8)
      64: owner         (32)
      96: executable    (1)
      97: padding       (7)
     104: hash          (32) */
  fd_memset( hdr, 0, 136UL );
  ulong lamports = 1UL;
  FD_STORE( ulong, hdr+0UL,  lamports );
  FD_STORE( ulong, hdr+8UL,  data_len );
  FD_STORE( ulong, hdr+48UL, lamports );
  hdr[96] = (uchar)executable;
}

static void
test_truncated_tar( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing truncated tar" ));
  ulong sz;

  /* Complete tar stream with EOF blocks. */
  fd_ssparse_reset( p );
  sz = build_minimal_snapshot( tar_buf, sizeof(tar_buf), 1 );
  FD_TEST( feed_all( p, tar_buf, sz )==FD_SSPARSE_ADVANCE_DONE );

  /* Missing both EOF blocks. */
  fd_ssparse_reset( p );
  sz = build_minimal_snapshot( tar_buf, sizeof(tar_buf), 0 );
  FD_TEST( feed_all( p, tar_buf, sz )!=FD_SSPARSE_ADVANCE_DONE );

  /* Only one zero block (partial EOF). */
  fd_ssparse_reset( p );
  sz = build_minimal_snapshot( tar_buf, sizeof(tar_buf), 0 );
  FD_TEST( sz + 512UL <= sizeof(tar_buf) );
  fd_memset( tar_buf+sz, 0, 512UL );
  sz += 512UL;
  FD_TEST( feed_all( p, tar_buf, sz )!=FD_SSPARSE_ADVANCE_DONE );

  /* Byte-by-byte feeding (complete). */
  fd_ssparse_reset( p );
  sz = build_minimal_snapshot( tar_buf, sizeof(tar_buf), 1 );
  FD_TEST( feed_bytewise( p, tar_buf, sz )==FD_SSPARSE_ADVANCE_DONE );

  /* Byte-by-byte feeding (missing EOF). */
  fd_ssparse_reset( p );
  sz = build_minimal_snapshot( tar_buf, sizeof(tar_buf), 0 );
  FD_TEST( feed_bytewise( p, tar_buf, sz )!=FD_SSPARSE_ADVANCE_DONE );

  /* Byte-by-byte feeding (partial EOF). */
  fd_ssparse_reset( p );
  sz = build_minimal_snapshot( tar_buf, sizeof(tar_buf), 0 );
  FD_TEST( sz + 512UL <= sizeof(tar_buf) );
  fd_memset( tar_buf+sz, 0, 512UL );
  sz += 512UL;
  FD_TEST( feed_bytewise( p, tar_buf, sz )!=FD_SSPARSE_ADVANCE_DONE );
}

static void
test_tar_header_errors( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing tar header errors" ));
  ulong off;
  fd_ssparse_advance_result_t result[1];
  int res;

  /* Bad magic (non-zero, non-ustar). */
  fd_ssparse_reset( p );
  fd_memset( tar_buf, 0x41, 512UL ); /* all 'A' bytes */
  FD_TEST( feed_all( p, tar_buf, 512UL )==FD_SSPARSE_ADVANCE_ERROR );

  /* Valid tar header after a zero frame. */
  fd_ssparse_reset( p );
  off = 0UL;
  fd_memset( tar_buf, 0, 512UL );
  off += 512UL;
  write_tar_header( tar_buf+off, "version", 5UL );
  off += 512UL;
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );

  /* Directory entry with non-zero size. */
  fd_ssparse_reset( p );
  write_tar_header_typed( tar_buf, "somedir", 100UL, FD_TAR_TYPE_DIR );
  FD_TEST( feed_all( p, tar_buf, 512UL )==FD_SSPARSE_ADVANCE_ERROR );

  /* Directory entry with zero size should be skipped. */
  fd_ssparse_reset( p );
  write_tar_header_typed( tar_buf, "somedir", 0UL, FD_TAR_TYPE_DIR );
  /* Should return AGAIN (skip), not ERROR */
  res = fd_ssparse_advance( p, tar_buf, 512UL, result );
  FD_TEST( res==FD_SSPARSE_ADVANCE_AGAIN );

  /* Unsupported typeflag (symlink). */
  fd_ssparse_reset( p );
  write_tar_header_typed( tar_buf, "version", 5UL, FD_TAR_TYPE_SYM_LINK );
  FD_TEST( feed_all( p, tar_buf, 512UL )==FD_SSPARSE_ADVANCE_ERROR );

  /* Regular file with zero size. */
  fd_ssparse_reset( p );
  write_tar_header( tar_buf, "version", 0UL );
  FD_TEST( feed_all( p, tar_buf, 512UL )==FD_SSPARSE_ADVANCE_ERROR );

  /* Unknown file name. */
  fd_ssparse_reset( p );
  write_tar_header( tar_buf, "dummy", 10UL );
  FD_TEST( feed_all( p, tar_buf, 512UL )==FD_SSPARSE_ADVANCE_ERROR );
}

static void
test_version( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing version" ));
  ulong off;

  /* Wrong version string. */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version", (uchar const *)"2.0.0", 5UL );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );

  /* Wrong version size (4 bytes). */
  fd_ssparse_reset( p );
  write_tar_header( tar_buf, "version", 4UL );
  FD_TEST( feed_all( p, tar_buf, 512UL )==FD_SSPARSE_ADVANCE_ERROR );

  /* Wrong version size (6 bytes). */
  fd_ssparse_reset( p );
  write_tar_header( tar_buf, "version", 6UL );
  FD_TEST( feed_all( p, tar_buf, 512UL )==FD_SSPARSE_ADVANCE_ERROR );
}

static void
test_duplicates( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing duplicates" ));
  ulong off;

  /* Duplicate version. */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version", (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version", (uchar const *)"1.2.0", 5UL );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );

  /* Duplicate manifest. */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB", 1UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/200", (uchar const *)"\xAB", 1UL );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );

  /* Duplicate status cache. */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/status_cache", (uchar const *)"\xCD", 1UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/status_cache", (uchar const *)"\xCD", 1UL );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );
}

static void
test_ordering( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing ordering" ));
  ulong off;
  uchar acc_content[136+8];

  /* Accounts before manifest. */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version", (uchar const *)"1.2.0", 5UL );
  build_account_header( acc_content, 8UL, 0 );
  fd_memset( acc_content+136, 0, 8UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/0.0", acc_content, sizeof(acc_content) );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );

  /* Premature EOF: missing version. */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100",          (uchar const *)"\xAB", 1UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/status_cache", (uchar const *)"\xCD", 1UL );
  off = append_eof( tar_buf, sizeof(tar_buf), off );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );

  /* Premature EOF: missing manifest. */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",                (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/status_cache", (uchar const *)"\xCD",  1UL );
  off = append_eof( tar_buf, sizeof(tar_buf), off );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );

  /* Premature EOF: missing status_cache. */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
  off = append_eof( tar_buf, sizeof(tar_buf), off );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );

  /* Valid ordering: manifest -> version -> status_cache. */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100",          (uchar const *)"\xAB",  1UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",                (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/status_cache", (uchar const *)"\xCD",  1UL );
  off = append_eof( tar_buf, sizeof(tar_buf), off );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_DONE );

  /* Valid ordering: status_cache -> manifest -> version. */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/status_cache", (uchar const *)"\xCD",  1UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100",          (uchar const *)"\xAB",  1UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",                (uchar const *)"1.2.0", 5UL );
  off = append_eof( tar_buf, sizeof(tar_buf), off );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_DONE );
}

static void
test_account_header( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing account header" ));
  ulong off;
  ulong slots[2], ids[2], fsz[2];
  uchar acc[512];

  /* Account with data_len exceeding FD_RUNTIME_ACC_SZ_MAX. */
  fd_ssparse_reset( p );
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = 136UL + 8UL;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 1UL )==0 );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
  fd_memset( acc, 0, sizeof(acc) );
  build_account_header( acc, FD_RUNTIME_ACC_SZ_MAX + 1UL, 0 );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/0.0", acc, 136UL + 8UL );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );

  /* Account with invalid executable flag. */
  fd_ssparse_reset( p );
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = 136UL + 8UL;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 1UL )==0 );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
  fd_memset( acc, 0, sizeof(acc) );
  build_account_header( acc, 8UL, 2 ); /* executable=2, invalid */
  fd_memset( acc+136, 0, 8UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/0.0", acc, 136UL + 8UL );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );

  /* Account with executable = 0 and 1 (both valid). */
  fd_ssparse_reset( p );
  ulong fsz0 = 136UL + 4UL;
  ulong fsz1 = 136UL + 4UL;
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = fsz0;
  slots[1] = 0UL; ids[1] = 1UL; fsz[1] = fsz1;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 2UL )==0 );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
  /* ... account with executable=0. */
  fd_memset( acc, 0, sizeof(acc) );
  build_account_header( acc, 4UL, 0 );
  fd_memset( acc+136, 0xAA, 4UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/0.0", acc, fsz0 );
  /* ... account with executable=1. */
  fd_memset( acc, 0, sizeof(acc) );
  build_account_header( acc, 4UL, 1 );
  fd_memset( acc+136, 0xBB, 4UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/0.1", acc, fsz1 );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/status_cache", (uchar const *)"\xCD", 1UL );
  off = append_eof( tar_buf, sizeof(tar_buf), off );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_DONE );
}

static void
test_acc_vec_map( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing acc vec map" ));
  ulong off;
  ulong slots[2], ids[2], fsz[2];
  uchar acc[512];

  /* acc_vec_map is empty, allow any AppendVec */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
  fd_memset( acc, 0, sizeof(acc) );
  build_account_header( acc, 8UL, 0 );
  fd_memset( acc+136, 0, 8UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/99.99", acc, 136UL + 8UL );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ACCOUNT_DATA );

  /* Account file not in acc_vec_map. */
  fd_ssparse_reset( p );
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = 2000UL;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 1UL )==0 );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
  fd_memset( acc, 0, sizeof(acc) );
  build_account_header( acc, 8UL, 0 );
  fd_memset( acc+136, 0, 8UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/99.99", acc, 136UL + 8UL );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );

  /* acc_vec file_sz > tar file_bytes. */
  fd_ssparse_reset( p );
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = 2000UL;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 1UL )==0 );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
  fd_memset( acc, 0, sizeof(acc) );
  build_account_header( acc, 8UL, 0 );
  fd_memset( acc+136, 0, 8UL );
  /* Tar entry says only 200 bytes, but acc_vec says 2000. */
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/0.0", acc, 200UL );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );

  /* Invalid account name (no dot). */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
  fd_memset( acc, 0, sizeof(acc) );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/100", acc, 144UL );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );

  /* Duplicate key in populate. */
  fd_ssparse_reset( p );
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = 144UL;
  slots[1] = 0UL; ids[1] = 0UL; fsz[1] = 144UL; /* duplicate (0,0) */
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 2UL )==-1 );
}

static void
test_account_data( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing account data" ));
  ulong off;
  ulong slots[1], ids[1], fsz[1];
  uchar acc[512];

  /* Complete snapshot with one account (acc_vec_bytes < tar file_bytes,
     producing garbage region). */
  fd_ssparse_reset( p );
  ulong data_len   = 16UL;
  ulong acc_vec_sz = 136UL + data_len;
  ulong tar_sz     = acc_vec_sz + 48UL; /* 48 bytes of garbage at end */
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = acc_vec_sz;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 1UL )==0 );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
  fd_memset( acc, 0, sizeof(acc) );
  build_account_header( acc, data_len, 0 );
  fd_memset( acc+136, 0xDD, data_len ); /* account data */
  fd_memset( acc+136+data_len, 0xFF, 48UL ); /* garbage */
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/0.0", acc, tar_sz );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/status_cache", (uchar const *)"\xCD", 1UL );
  off = append_eof( tar_buf, sizeof(tar_buf), off );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_DONE );

  /* Account with zero data_len. */
  fd_ssparse_reset( p );
  acc_vec_sz = 136UL; /* header only, no data */
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = acc_vec_sz;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 1UL )==0 );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
  fd_memset( acc, 0, 136UL );
  build_account_header( acc, 0UL, 0 );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/0.0", acc, acc_vec_sz );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/status_cache", (uchar const *)"\xCD", 1UL );
  off = append_eof( tar_buf, sizeof(tar_buf), off );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_DONE );
}

static void
test_reset( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing reset" ));
  ulong off;
  ulong sz;

  /* Parse, reset, parse again. */
  fd_ssparse_reset( p );
  sz = build_minimal_snapshot( tar_buf, sizeof(tar_buf), 1 );
  FD_TEST( feed_all( p, tar_buf, sz )==FD_SSPARSE_ADVANCE_DONE );
  fd_ssparse_reset( p );
  FD_TEST( feed_all( p, tar_buf, sz )==FD_SSPARSE_ADVANCE_DONE );

  /* Mid-stream reset. */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version", (uchar const *)"1.2.0", 5UL );
  feed_all( p, tar_buf, off );
  /* Reset mid-stream and parse a fresh complete snapshot. */
  fd_ssparse_reset( p );
  sz = build_minimal_snapshot( tar_buf, sizeof(tar_buf), 1 );
  FD_TEST( feed_all( p, tar_buf, sz )==FD_SSPARSE_ADVANCE_DONE );
}

static void
test_fragmentation( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing fragmentation" ));
  ulong off;
  ulong sz;
  ulong slots[1], ids[1], fsz[1];
  uchar acc[256];
  fd_ssparse_advance_result_t result[1];
  int res;

  /* Feed tar header in two halves. */
  fd_ssparse_reset( p );
  sz = build_minimal_snapshot( tar_buf, sizeof(tar_buf), 1 );
  res = fd_ssparse_advance( p, tar_buf, 256UL, result );
  FD_TEST( res==FD_SSPARSE_ADVANCE_AGAIN );
  FD_TEST( result->bytes_consumed==256UL );
  res = feed_all( p, tar_buf+256UL, sz-256UL );
  FD_TEST( res==FD_SSPARSE_ADVANCE_DONE );

  /* Feed entire snapshot byte-by-byte with accounts. */
  fd_ssparse_reset( p );
  ulong data_len   = 8UL;
  ulong acc_vec_sz = 136UL + data_len;
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = acc_vec_sz;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 1UL )==0 );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
  fd_memset( acc, 0, sizeof(acc) );
  build_account_header( acc, data_len, 1 );
  fd_memset( acc+136, 0xEE, data_len );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/0.0", acc, acc_vec_sz );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/status_cache", (uchar const *)"\xCD", 1UL );
  off = append_eof( tar_buf, sizeof(tar_buf), off );
  FD_TEST( feed_bytewise( p, tar_buf, off )==FD_SSPARSE_ADVANCE_DONE );
}

static void
test_advance_after_done( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing advance after done" ));
  ulong sz;
  uchar extra[512];
  fd_ssparse_advance_result_t result[1];
  int res;

  /* Feed zeros after DONE. */
  fd_ssparse_reset( p );
  sz = build_minimal_snapshot( tar_buf, sizeof(tar_buf), 1 );
  FD_TEST( feed_all( p, tar_buf, sz )==FD_SSPARSE_ADVANCE_DONE );
  fd_memset( extra, 0, sizeof(extra) );
  res = fd_ssparse_advance( p, extra, 512UL, result );
  FD_TEST( res==FD_SSPARSE_ADVANCE_DONE );

  /* Feed valid header after DONE. */
  fd_ssparse_reset( p );
  sz = build_minimal_snapshot( tar_buf, sizeof(tar_buf), 1 );
  FD_TEST( feed_all( p, tar_buf, sz )==FD_SSPARSE_ADVANCE_DONE );
  write_tar_header( extra, "version", 5UL );
  res = fd_ssparse_advance( p, extra, 512UL, result );
  FD_TEST( res==FD_SSPARSE_ADVANCE_ERROR );

  /* Feed garbage after DONE. */
  fd_ssparse_reset( p );
  sz = build_minimal_snapshot( tar_buf, sizeof(tar_buf), 1 );
  FD_TEST( feed_all( p, tar_buf, sz )==FD_SSPARSE_ADVANCE_DONE );
  fd_memset( extra, 0x41, sizeof(extra) );
  res = fd_ssparse_advance( p, extra, 512UL, result );
  FD_TEST( res==FD_SSPARSE_ADVANCE_ERROR );
}

static void
test_truncation_mid_content( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing truncation mid content" ));
  ulong off;
  ulong slots[1], ids[1], fsz[1];
  uchar acc[136+32];
  int res;

  /* Truncated mid-version. */
  fd_ssparse_reset( p );
  write_tar_header( tar_buf, "version", 5UL );
  fd_memcpy( tar_buf+512, "1.2", 3UL );
  res = feed_all( p, tar_buf, 512UL + 3UL );
  FD_TEST( res!=FD_SSPARSE_ADVANCE_DONE );
  FD_TEST( res!=FD_SSPARSE_ADVANCE_ERROR );

  /* Truncated mid-manifest */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version", (uchar const *)"1.2.0", 5UL );
  write_tar_header( tar_buf+off, "snapshots/100", 100UL );
  off += 512UL;
  fd_memset( tar_buf+off, 0xAB, 50UL );
  off += 50UL;
  res = feed_all( p, tar_buf, off );
  FD_TEST( res!=FD_SSPARSE_ADVANCE_DONE );

  /* Truncated mid-account-data. */
  fd_ssparse_reset( p );
  ulong data_len   = 64UL;
  ulong acc_vec_sz = 136UL + data_len;
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = acc_vec_sz;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 1UL )==0 );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
  /* ... write account tar entry header for full size, but only provide
     the 136-byte account header + half the data (32 of 64 bytes). */
  write_tar_header( tar_buf+off, "accounts/0.0", acc_vec_sz );
  off += 512UL;
  fd_memset( acc, 0, sizeof(acc) );
  build_account_header( acc, data_len, 0 );
  fd_memset( acc+136, 0xDD, 32UL );
  fd_memcpy( tar_buf+off, acc, sizeof(acc) );
  off += sizeof(acc);
  res = feed_all( p, tar_buf, off );
  FD_TEST( res!=FD_SSPARSE_ADVANCE_DONE );

  /* Truncated mid-status-cache. */
  fd_ssparse_reset( p );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
  write_tar_header( tar_buf+off, "snapshots/status_cache", 80UL );
  off += 512UL;
  fd_memset( tar_buf+off, 0xCD, 40UL );
  off += 40UL;
  res = feed_all( p, tar_buf, off );
  FD_TEST( res!=FD_SSPARSE_ADVANCE_DONE );

  /* Truncated mid-tar-header. */
  fd_ssparse_reset( p );
  write_tar_header( tar_buf, "version", 5UL );
  res = feed_all( p, tar_buf, 256UL );
  FD_TEST( res!=FD_SSPARSE_ADVANCE_DONE );
  FD_TEST( res!=FD_SSPARSE_ADVANCE_ERROR );
}

static void
test_multi_account_non_aligned( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing multi account non aligned" ));

  /* Two accounts in one acc_vec with non-8-aligned data_len.
     Exercises advance_account_padding with real padding bytes
     and the PADDING -> ACCOUNT_HEADER loop. */
  ulong dl1  = 5UL, dl2 = 3UL;
  ulong a1   = fd_ulong_align_up( 136UL+dl1, 8UL ); /* 144 */
  ulong avsz = a1 + 136UL + dl2;                     /* 283 */
  ulong off;
  ulong slots[1], ids[1], fsz[1];

  uchar acc[512];
  fd_memset( acc, 0, sizeof(acc) );
  build_account_header( acc, dl1, 0 );
  fd_memset( acc+136, 0xAA, dl1 );
  build_account_header( acc+a1, dl2, 1 );
  fd_memset( acc+a1+136, 0xBB, dl2 );

  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",                (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100",          (uchar const *)"\xAB",  1UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/0.0",           acc, avsz );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/status_cache", (uchar const *)"\xCD",  1UL );
  off = append_eof( tar_buf, sizeof(tar_buf), off );

  fd_ssparse_reset( p );
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = avsz;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 1UL )==0 );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_DONE );

  fd_ssparse_reset( p );
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = avsz;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 1UL )==0 );
  FD_TEST( feed_bytewise( p, tar_buf, off )==FD_SSPARSE_ADVANCE_DONE );
}

static void
test_account_garbage_partial_header( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing account garbage partial header" ));

  /* acc_vec_bytes extends into a partial second header, with garbage
     bytes beyond.  Exercises SCROLL_ACCOUNT_GARBAGE via partial header
     path in advance_account_header. */
  fd_ssparse_reset( p );
  ulong acc_vec_sz = 136UL + 8UL + 4UL; /* 1 account (144) + 4 partial header bytes */
  ulong tar_sz     = acc_vec_sz + 52UL;  /* plus garbage */
  ulong slots[1], ids[1], fsz[1];
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = acc_vec_sz;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 1UL )==0 );

  uchar acc[256];
  fd_memset( acc, 0, sizeof(acc) );
  build_account_header( acc, 8UL, 0 );
  fd_memset( acc+136, 0xDD, 8UL );

  ulong off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",                (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100",          (uchar const *)"\xAB",  1UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/0.0",           acc, tar_sz );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/status_cache", (uchar const *)"\xCD",  1UL );
  off = append_eof( tar_buf, sizeof(tar_buf), off );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_DONE );
}

static void
test_account_data_overflow( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing account data overflow" ));

  /* Account header claims data_len=16 but acc_vec only has 8 bytes of
     room for data.  Exercises error in advance_account_data. */
  fd_ssparse_reset( p );
  ulong acc_vec_sz = 136UL + 8UL;
  ulong slots[1], ids[1], fsz[1];
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = acc_vec_sz;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 1UL )==0 );

  uchar acc[256];
  fd_memset( acc, 0, sizeof(acc) );
  build_account_header( acc, 16UL, 0 ); /* data_len=16 but only 8 available */
  fd_memset( acc+136, 0xDD, 8UL );

  ulong off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/0.0",  acc, acc_vec_sz );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );
}

static void
test_batch( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing batch" ));

  ulong n    = FD_SSPARSE_ACC_BATCH_MAX; /* 8 */
  ulong avsz = n * 136UL;               /* 1088 */
  ulong off;
  ulong slots[1], ids[1], fsz[1];
  uchar acc[1088];

  /* Successful batch with 8 zero-data accounts. */
  fd_ssparse_reset( p );
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = avsz;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 1UL )==0 );
  fd_ssparse_batch_enable( p, 1 );
  fd_memset( acc, 0, sizeof(acc) );
  for( ulong i=0; i<n; i++ ) build_account_header( acc+i*136UL, 0UL, 0 );
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",                (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100",          (uchar const *)"\xAB",  1UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/0.0",           acc, avsz );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/status_cache", (uchar const *)"\xCD",  1UL );
  off = append_eof( tar_buf, sizeof(tar_buf), off );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_DONE );

  /* ConfigProgram-owned account at front aborts batch (slow path). */
  fd_ssparse_reset( p );
  slots[0] = 0UL; ids[0] = 0UL; fsz[0] = avsz;
  FD_TEST( fd_ssparse_populate_acc_vec_map( p, slots, ids, fsz, 1UL )==0 );
  fd_ssparse_batch_enable( p, 1 );
  fd_memset( acc, 0, sizeof(acc) );
  for( ulong i=0; i<n; i++ ) build_account_header( acc+i*136UL, 0UL, 0 );
  uchar config_owner[32] = { CONFIG_PROG_ID };
  fd_memcpy( acc+64, config_owner, 32 ); /* first account's owner */
  off = 0UL;
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",                (uchar const *)"1.2.0", 5UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100",          (uchar const *)"\xAB",  1UL );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "accounts/0.0",           acc, avsz );
  off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/status_cache", (uchar const *)"\xCD",  1UL );
  off = append_eof( tar_buf, sizeof(tar_buf), off );
  FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_DONE );

  fd_ssparse_batch_enable( p, 0 );
}

static void
test_parse_name_edge_cases( fd_ssparse_t * p ) {
  FD_LOG_NOTICE(( "testing parse name edge cases" ));

  uchar dummy[256];
  fd_memset( dummy, 0, sizeof(dummy) );

  char const * bad_names[] = {
    "accounts/.0",                     /* empty slot */
    "accounts/0.",                     /* empty id */
    "accounts/0.abc",                  /* non-numeric id */
    "accounts/99999999999999999999.0", /* ERANGE overflow */
  };

  ulong off;
  for( ulong i=0; i<4UL; i++ ) {
    fd_ssparse_reset( p );
    off = 0UL;
    off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "version",       (uchar const *)"1.2.0", 5UL );
    off = append_tar_entry( tar_buf, sizeof(tar_buf), off, "snapshots/100", (uchar const *)"\xAB",  1UL );
    off = append_tar_entry( tar_buf, sizeof(tar_buf), off, bad_names[i],    dummy, 144UL );
    FD_TEST( feed_all( p, tar_buf, off )==FD_SSPARSE_ADVANCE_ERROR );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  void * parser_mem = aligned_alloc( fd_ssparse_align(), fd_ssparse_footprint( 64UL ) );
  FD_TEST( parser_mem );

  fd_ssparse_t * p = fd_ssparse_join( fd_ssparse_new( parser_mem, 64UL, 42UL ) );
  FD_TEST( p );

  test_truncated_tar( p );
  test_tar_header_errors( p );
  test_version( p );
  test_duplicates( p );
  test_ordering( p );
  test_account_header( p );
  test_acc_vec_map( p );
  test_account_data( p );
  test_reset( p );
  test_fragmentation( p );
  test_advance_after_done( p );
  test_truncation_mid_content( p );
  test_multi_account_non_aligned( p );
  test_account_garbage_partial_header( p );
  test_account_data_overflow( p );
  test_batch( p );
  test_parse_name_edge_cases( p );

  free( fd_ssparse_delete( fd_ssparse_leave( p ) ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
