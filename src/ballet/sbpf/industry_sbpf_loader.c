#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

/* interface to comply with */
#include "../../../contrib/industry.h"

#include "../../util/sanitize/fd_fuzz.h"
#include "fd_sbpf_loader.h"
#include "fd_sbpf_maps.c"

#include <assert.h>
#include <stdlib.h>


uint const _syscalls[] = {
  0xb6fc1a11, 0x686093bb, 0x207559bd, 0x5c2a3178, 0x52ba5096,
  0x7ef088ca, 0x9377323c, 0x48504a38, 0x11f49d86, 0xd7793abb,
  0x17e40350, 0x174c5122, 0xaa2607ca, 0xdd1c41a6, 0xd56b5fe9,
  0x23a29a61, 0x3b97b73c, 0xbf7188f6, 0x717cc4a3, 0x434371f8,
  0x5fdcde31, 0x3770fb22, 0xa22b9c85, 0xd7449092, 0x83f00e8f,
  0xa226d3eb, 0x5d2245e4, 0x7317b434, 0xadb8efc8, 0x85532d94,
  0U
};


int
industry_init( int  *   argc,
               char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  return 0;
}


int
industry_exit( void ) {
  fd_halt();
  return 0;
}


static void
set_error( unsigned long * out_result_sz,
           void *          out_result_buf,
           unsigned long   result_buf_sz ) {
  assert( result_buf_sz >= sizeof(int32_t) );

  int32_t * res_out = (int32_t *) out_result_buf;
  *res_out = -1;
  *out_result_sz = sizeof(int32_t);
}

int
industry_test_one( unsigned long * out_result_sz,
                   unsigned char * out_result_buf,
                   unsigned long   result_buf_sz,
                   unsigned char * data,
                   unsigned long   data_sz ) {
    int retval = 0;
    /* The layout of result (out_result_buf) is:
         - i32: 0 if unpack succeded, -1 if failed
         - u64: len of rodata:
         - uchar[]: rodata
         - u64: entry_pc
         - i64: text_off
         - u64: text_sz */ 

  fd_sbpf_elf_info_t info;
  if( FD_UNLIKELY( !fd_sbpf_elf_peek( &info, data, data_sz ) ) ) {
    set_error( out_result_sz, out_result_buf, result_buf_sz );
    return 0;
  }

  /* Allocate objects */

  void * rodata = malloc( info.rodata_footprint );
  FD_TEST( rodata );

  fd_sbpf_program_t * prog = fd_sbpf_program_new( aligned_alloc( fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) ), &info, rodata );
  FD_TEST( prog );

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
  FD_TEST( syscalls );

  for( uint const * x = _syscalls; *x; x++ )
    fd_sbpf_syscalls_insert( syscalls, *x );

  /* Load program */
  int res = fd_sbpf_program_load( prog, data, data_sz, syscalls );

  if ( !res ) {
    set_error( out_result_sz, out_result_buf, result_buf_sz );
    goto cleanup;
  }
  
  off_t cursor = 0;

  /* - i32: 0 if unpack succeded, -1 if failed */
  int32_t * res_out = (int32_t *) &out_result_buf[cursor];
  cursor += sizeof(int32_t);
  *res_out = 0;

  /* - u64: len of rodata */
  u_int64_t * len_rodata = (u_int64_t *) &out_result_buf[cursor];
  cursor += sizeof(u_int64_t);
  *len_rodata = prog->rodata_sz;

  /* - uchar[]: rodata */
  memcpy(out_result_buf + cursor, prog->rodata, prog->rodata_sz);
  cursor += prog->rodata_sz;

  /* - u64: entry_pc */
  u_int64_t * entry_pc = (u_int64_t *) &out_result_buf[cursor];
  cursor += sizeof(u_int64_t);
  *entry_pc = prog->entry_pc;

  /* - i64: text_off */
  int64_t * text_off = (int64_t *) &out_result_buf[cursor];
  cursor += sizeof(int64_t);
  *text_off = (uchar *)prog->text - (uchar *)prog->rodata;

  /* - u64: text_sz */
  u_int64_t * text_sz = (u_int64_t *) &out_result_buf[cursor];
  cursor += sizeof(u_int64_t);
  *text_sz = prog->text_cnt * 8;

  /* set the output buffer size based on the cursor */
  *out_result_sz = (unsigned long) cursor;

cleanup:
  /* clean up */
  free( fd_sbpf_syscalls_delete( syscalls ) );
  free( fd_sbpf_program_delete( prog ) );
  free( rodata );

  return retval;
}
