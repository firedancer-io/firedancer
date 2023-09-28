#include <stddef.h>
#include <stdlib.h>

#include "../nanopb/pb_decode.h"
#include "../nanopb/pb_encode.h"
#include "../fd_flamenco.h"
#include "fd_trace.pb.h"
#include "fd_txntrace.h"

/* Setup **************************************************************/

/* fuzz_txntrace_mode specifies the permitted mutate mode */

static uint        fuzz_txntrace_mode;  /* mode param */
static fd_wksp_t * fuzz_txntrace_wksp;

static void
fuzz_txntrace_exit( void ) {
  fd_wksp_free_laddr( fd_scratch_detach( NULL ) );
  fd_wksp_delete( fd_wksp_leave( fuzz_txntrace_wksp ) );
  fd_flamenco_halt();
  fd_halt();
}

int
LLVMFuzzerInitialize( int  *   pargc,
                      char *** pargv ) {

  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( pargc, pargv );
  fd_flamenco_boot( pargc, pargv );
  atexit( fuzz_txntrace_exit );

  /* Command-line arguments */
  fuzz_txntrace_mode      = fd_env_strip_cmdline_uint ( pargc, pargv, "--txn-mutate", NULL, 0U       );
  char const * _page_sz   = fd_env_strip_cmdline_cstr ( pargc, pargv, "--page-sz",    NULL, "normal" );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong( pargc, pargv, "--page-cnt",   NULL, 2UL      );
  ulong        scratch_mb = fd_env_strip_cmdline_ulong( pargc, pargv, "--scratch-mb", NULL, 1024UL   );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  /* Create workspace and scratch allocator */

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_log_cpu_id(), "wksp", 0UL );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_new_anonymous() failed" ));

  ulong  smax = scratch_mb << 20;
  void * smem = fd_wksp_alloc_laddr( wksp, fd_scratch_smem_align(), smax, 1UL );
  if( FD_UNLIKELY( !smem ) ) FD_LOG_ERR(( "Failed to alloc scratch mem" ));

# define SCRATCH_DEPTH (64UL)
  static FD_TLS ulong fmem[ SCRATCH_DEPTH ];
  fd_scratch_attach( smem, fmem, smax, SCRATCH_DEPTH );

  return 0;
}

/* Custom Mutator *****************************************************/

/* LLVMFuzzerMutate is an API function provided by libFuzzer. */

extern ulong
LLVMFuzzerMutate( uchar * data,
                  ulong   sz,
                  ulong   max_sz );

/* FD_TXNTRACE_MUTATE_{...} lists available mutation modes. */

#define FD_TXNTRACE_MUTATE_ALL             (0U)  /* mutate everything */
#define FD_TXNTRACE_MUTATE_ACCT_CNT        (1U)  /* add/remove txn account */
#define FD_TXNTRACE_MUTATE_ACCT_ADDR       (2U)  /* corrupt acct addr */
#define FD_TXNTRACE_MUTATE_ACCT_PERM       (3U)  /* change acct perm */
#define FD_TXNTRACE_MUTATE_ACCT_META       (4U)  /* change acct meta */
#define FD_TXNTRACE_MUTATE_ACCT_DATA       (5U)  /* mutate acct content */
#define FD_TXNTRACE_MUTATE_INSTR_ACCT_CNT  (6U)  /* add/remove instr accts */
#define FD_TXNTRACE_MUTATE_INSTR_ACCT      (7U)  /* replace instr acct */
#define FD_TXNTRACE_MUTATE_INSTR_DATA      (8U)  /* change instr data */
#define FD_TXNTRACE_MUTATE_MODE_CNT        (9U)  /* number of supported mutate modes */

static void
fd_txntrace_mutate_acct_cnt( fd_soltrace_TxnInput * input,
                             fd_rng_t *             rng ) {
  (void)input; (void)rng;
}

static void
fd_txntrace_mutate_acct_addr( fd_soltrace_TxnInput * input,
                              fd_rng_t *             rng ) {

  /* Flip a bit */
  ulong   acct_idx = fd_rng_ulong_roll( rng, input->account_count );
  uchar * addr     = input->transaction.account_keys[ acct_idx ];
  ulong   bit_idx  = fd_rng_ulong( rng ) & 255UL;

            addr[ bit_idx >> 3 ] =
  (uchar)( (addr[ bit_idx >> 3 ]) ^ (1UL<<( bit_idx & 7UL )) );

}

static void
fd_txntrace_mutate_acct_perm( fd_soltrace_TxnInput * input,
                              fd_rng_t *             rng ) {
  (void)input; (void)rng;
}

static void
fd_txntrace_mutate_acct_meta( fd_soltrace_TxnInput * input,
                              fd_rng_t *             rng ) {
  (void)input; (void)rng;
}

static void
fd_txntrace_mutate_acct_data( fd_soltrace_TxnInput * input,
                              fd_rng_t *             rng ) {

  ulong              acct_idx = fd_rng_ulong_roll( rng, input->account_count );
  pb_bytes_array_t * data     = input->account[ acct_idx ].data;

  /* Raw account data mutate.
     TODO add program-aware mutate
     TODO support growing data */
  data->size = (ushort)LLVMFuzzerMutate( data->bytes, data->size, data->size );

}

static void
fd_txntrace_mutate_instr_acct_cnt( fd_soltrace_TxnInput * input,
                                   fd_rng_t *             rng ) {
  (void)input; (void)rng;
}

static void
fd_txntrace_mutate_instr_acct( fd_soltrace_TxnInput * input,
                               fd_rng_t *             rng ) {
  (void)input; (void)rng;
}

static void
fd_txntrace_mutate_instr_data( fd_soltrace_TxnInput * input,
                               fd_rng_t *             rng ) {

  ulong              instr_idx = fd_rng_ulong_roll( rng, input->transaction.instructions_count );
  pb_bytes_array_t * data      = input->transaction.instructions[ instr_idx ].data;

  /* Raw instruction data mutate.
     TODO add program-aware mutate
     TODO support growing data */
  data->size = (ushort)LLVMFuzzerMutate( data->bytes, data->size, data->size );

}

/* fd_txntrace_mutate randomly mutates a TxnExecInput.  May do alloc
   calls to libc malloc/realloc/free.  Randomness is deterministically
   sourced from rng.  mode is one of FD_TXNTRACE_MUTATE_{...}. */

void
fd_txntrace_mutate( fd_soltrace_TxnInput * input,
                    fd_rng_t *             rng,
                    uint                   mode ) {
  switch( mode ) {
  case FD_TXNTRACE_MUTATE_ACCT_CNT:
    fd_txntrace_mutate_acct_cnt( input, rng ); break;
  case FD_TXNTRACE_MUTATE_ACCT_ADDR:
    fd_txntrace_mutate_acct_addr( input, rng ); break;
  case FD_TXNTRACE_MUTATE_ACCT_PERM:
    fd_txntrace_mutate_acct_perm( input, rng ); break;
  case FD_TXNTRACE_MUTATE_ACCT_META:
    fd_txntrace_mutate_acct_meta( input, rng ); break;
  case FD_TXNTRACE_MUTATE_ACCT_DATA:
    fd_txntrace_mutate_acct_data( input, rng ); break;
  case FD_TXNTRACE_MUTATE_INSTR_ACCT_CNT:
    fd_txntrace_mutate_instr_acct_cnt( input, rng ); break;
  case FD_TXNTRACE_MUTATE_INSTR_ACCT:
    fd_txntrace_mutate_instr_acct( input, rng ); break;
  case FD_TXNTRACE_MUTATE_INSTR_DATA:
    fd_txntrace_mutate_instr_data( input, rng ); break;
  }
}

ulong
LLVMFuzzerCustomMutator( uchar * data,
                         ulong   sz,
                         ulong   max_sz,
                         uint    seed ) {
  /* Create deterministically seeded RNG */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  /* Deserialize */
  pb_istream_t stream = pb_istream_from_buffer( data, sz );
  fd_soltrace_TxnInput in[1];
  fd_memset( in, 0, sizeof(fd_soltrace_TxnInput) );
  if( FD_UNLIKELY( !pb_decode( &stream, fd_soltrace_TxnInput_fields, in ) ) )
    return 0UL;  /* cannot mutate invalid Protobuf */

  /* Select mutate mode */
  uint mode;
  if( fuzz_txntrace_mode==FD_TXNTRACE_MUTATE_ALL )
    mode = fd_rng_uint_roll( rng, FD_TXNTRACE_MUTATE_MODE_CNT );
  else
    mode = fuzz_txntrace_mode;

  /* Mutate */
  fd_txntrace_mutate( in, rng, mode );

  /* Re-serialize */
  pb_ostream_t ostream = pb_ostream_from_buffer( data, max_sz );
  if( FD_UNLIKELY( !pb_encode( &ostream, fd_soltrace_TxnInput_fields, in ) ) )
    return 0UL;  /* cannot mutate, insufficient output space */

  /* Clean up */
  pb_release( fd_soltrace_TxnInput_fields, in );
  fd_rng_delete( fd_rng_leave( rng ) );
  return ostream.bytes_written;
}

/* Fuzz Target ********************************************************/

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {

  FD_SCRATCH_SCOPED_FRAME;

  /* Deserialize */
  pb_istream_t stream = pb_istream_from_buffer( data, size );
  fd_soltrace_TxnInput in[1];
  fd_memset( in, 0, sizeof(fd_soltrace_TxnInput) );
  if( FD_UNLIKELY( !pb_decode( &stream, fd_soltrace_TxnInput_fields, in ) ) )
    return -1;

  /* Execute */
  fd_soltrace_TxnDiff  _diff[1];
  fd_soltrace_TxnDiff * diff = fd_txntrace_replay( _diff, in, fuzz_txntrace_wksp );
  if( FD_UNLIKELY( !diff ) )
    return -1;

  /* Clean up */
  fd_wksp_free_laddr( diff );
  pb_release( fd_soltrace_TxnInput_fields, in );

  return 0;
}
