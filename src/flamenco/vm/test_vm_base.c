#include "fd_vm_private.h"

/* Verify error codes */

FD_STATIC_ASSERT( FD_VM_SUCCESS                         ==  0, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INVAL                       == -1, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_AGAIN                       == -2, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_UNSUP                       == -3, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_PERM                        == -4, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_FULL                        == -5, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_EMPTY                       == -6, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_IO                          == -7, vm_err );

FD_STATIC_ASSERT( FD_VM_ERR_SIGTEXT                     == -8, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_SIGSPLIT                    == -9, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_SIGCALL                     ==-10, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_SIGSTACK                    ==-11, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_SIGILL                      ==-12, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_SIGSEGV                     ==-13, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_SIGBUS                      ==-14, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_SIGRDONLY                   ==-15, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_SIGCOST                     ==-16, vm_err );

FD_STATIC_ASSERT( FD_VM_ERR_ABORT                       ==-17, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_PANIC                       ==-18, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_MEM_OVERLAP                 ==-19, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INSTR_ERR                   ==-20, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INVOKE_CONTEXT_BORROW_FAILED==-21, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_RETURN_DATA_TOO_LARGE       ==-22, vm_err );

FD_STATIC_ASSERT( FD_VM_ERR_INVALID_OPCODE              ==-23, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INVALID_SRC_REG             ==-24, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INVALID_DST_REG             ==-25, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INF_LOOP                    ==-26, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_JMP_OUT_OF_BOUNDS           ==-27, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_JMP_TO_ADDL_IMM             ==-28, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INVALID_END_IMM             ==-29, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INCOMPLETE_LDQ              ==-30, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_LDQ_NO_ADDL_IMM             ==-31, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_NO_SUCH_EXT_CALL            ==-32, vm_err );

/* Verify limits */

FD_STATIC_ASSERT( FD_VM_REG_CNT       ==11UL, vm_reg );
FD_STATIC_ASSERT( FD_VM_REG_MAX       ==16UL, vm_reg );
FD_STATIC_ASSERT( FD_VM_SHADOW_REG_CNT== 4UL, vm_reg );

FD_STATIC_ASSERT( FD_VM_STACK_FRAME_MAX==64UL,          vm_stack );
FD_STATIC_ASSERT( FD_VM_STACK_FRAME_SZ ==0x1000UL,      vm_stack );
FD_STATIC_ASSERT( FD_VM_STACK_GUARD_SZ ==0x1000UL,      vm_stack );
FD_STATIC_ASSERT( FD_VM_STACK_MAX      ==64UL*0x2000UL, vm_stack );

FD_STATIC_ASSERT( FD_VM_HEAP_DEFAULT== 32UL*1024UL, vm_heap );
FD_STATIC_ASSERT( FD_VM_HEAP_MAX    ==256UL*1024UL, vm_heap );

FD_STATIC_ASSERT( FD_VM_LOG_MAX==10000UL, vm_log );

/* FIXME: COVER MEMORY MAP */

FD_STATIC_ASSERT( FD_VM_COMPUTE_UNIT_LIMIT                       ==         1400000UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_LOG_64_UNITS                             ==             100UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_CREATE_PROGRAM_ADDRESS_UNITS             ==            1500UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_INVOKE_UNITS                             ==            1000UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_MAX_INVOKE_STACK_HEIGHT                  ==               5UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_MAX_INSTRUCTION_TRACE_LENGTH             ==              64UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_SHA256_BASE_COST                         ==              85UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_SHA256_BYTE_COST                         ==               1UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_SHA256_MAX_SLICES                        ==           20000UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_MAX_CALL_DEPTH                           ==              64UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_STACK_FRAME_SIZE                         ==            4096UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_LOG_PUBKEY_UNITS                         ==             100UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_MAX_CPI_INSTRUCTION_SIZE                 ==            1280UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_CPI_BYTES_PER_UNIT                       ==             250UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_SYSVAR_BASE_COST                         ==             100UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_SECP256K1_RECOVER_COST                   ==           25000UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_SYSCALL_BASE_COST                        ==             100UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_CURVE25519_EDWARDS_VALIDATE_POINT_COST   ==             159UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_CURVE25519_EDWARDS_ADD_COST              ==             473UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_CURVE25519_EDWARDS_SUBTRACT_COST         ==             475UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_CURVE25519_EDWARDS_MULTIPLY_COST         ==            2177UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_CURVE25519_EDWARDS_MSM_BASE_COST         ==            2273UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_CURVE25519_EDWARDS_MSM_INCREMENTAL_COST  ==             758UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_CURVE25519_RISTRETTO_VALIDATE_POINT_COST ==             169UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_CURVE25519_RISTRETTO_ADD_COST            ==             521UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_CURVE25519_RISTRETTO_SUBTRACT_COST       ==             519UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_CURVE25519_RISTRETTO_MULTIPLY_COST       ==            2208UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_CURVE25519_RISTRETTO_MSM_BASE_COST       ==            2303UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_CURVE25519_RISTRETTO_MSM_INCREMENTAL_COST==             788UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_HEAP_SIZE                                ==           32768UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_HEAP_COST                                ==               8UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_MEM_OP_BASE_COST                         ==              10UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_ALT_BN128_ADDITION_COST                  ==             334UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_ALT_BN128_MULTIPLICATION_COST            ==            3840UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_ALT_BN128_PAIRING_ONE_PAIR_COST_FIRST    ==           36364UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_ALT_BN128_PAIRING_ONE_PAIR_COST_OTHER    ==           12121UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_BIG_MODULAR_EXPONENTIATION_COST          ==              33UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_POSEIDON_COST_COEFFICIENT_A              ==              61UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_POSEIDON_COST_COEFFICIENT_C              ==             542UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_GET_REMAINING_COMPUTE_UNITS_COST         ==             100UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_ALT_BN128_G1_COMPRESS                    ==              30UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_ALT_BN128_G1_DECOMPRESS                  ==             398UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_ALT_BN128_G2_COMPRESS                    ==              86UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_ALT_BN128_G2_DECOMPRESS                  ==           13610UL, vm_cu );
FD_STATIC_ASSERT( FD_VM_LOADED_ACCOUNTS_DATA_SIZE_LIMIT          ==64UL*1024UL*1024UL, vm_cu );

FD_STATIC_ASSERT( FD_VM_TRACE_EVENT_TYPE_EXE   ==0, vm_trace );
FD_STATIC_ASSERT( FD_VM_TRACE_EVENT_TYPE_READ  ==1, vm_trace );
FD_STATIC_ASSERT( FD_VM_TRACE_EVENT_TYPE_WRITE ==2, vm_trace );

#if 0 /* FIXME: MOVE TESTING TO VM */
static fd_vm_log_collector_t lc[1];
static uchar lc_mirror[ FD_VM_LOG_MAX ];
#endif

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong event_max      = fd_env_strip_cmdline_ulong( &argc, &argv, "--event-max",      NULL, 1024UL );
  ulong event_data_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--event-data-max", NULL,   64UL );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# define TEST( err ) FD_LOG_NOTICE(( "Testing fd_vm_strerror( %-38s ) (%i-%s)", #err, err, fd_vm_strerror( err ) ))
  TEST( FD_VM_SUCCESS                          );
  TEST( FD_VM_ERR_INVAL                        );
  TEST( FD_VM_ERR_AGAIN                        );
  TEST( FD_VM_ERR_UNSUP                        );
  TEST( FD_VM_ERR_PERM                         );
  TEST( FD_VM_ERR_FULL                         );
  TEST( FD_VM_ERR_EMPTY                        );
  TEST( FD_VM_ERR_IO                           );

  TEST( FD_VM_ERR_SIGTEXT                      );
  TEST( FD_VM_ERR_SIGSPLIT                     );
  TEST( FD_VM_ERR_SIGCALL                      );
  TEST( FD_VM_ERR_SIGSTACK                     );
  TEST( FD_VM_ERR_SIGILL                       );
  TEST( FD_VM_ERR_SIGSEGV                      );
  TEST( FD_VM_ERR_SIGBUS                       );
  TEST( FD_VM_ERR_SIGRDONLY                    );
  TEST( FD_VM_ERR_SIGCOST                      );

  TEST( FD_VM_ERR_ABORT                        );
  TEST( FD_VM_ERR_PANIC                        );
  TEST( FD_VM_ERR_MEM_OVERLAP                  );
  TEST( FD_VM_ERR_INSTR_ERR                    );
  TEST( FD_VM_ERR_INVOKE_CONTEXT_BORROW_FAILED );
  TEST( FD_VM_ERR_RETURN_DATA_TOO_LARGE        );

  TEST( FD_VM_ERR_INVALID_OPCODE               );
  TEST( FD_VM_ERR_INVALID_SRC_REG              );
  TEST( FD_VM_ERR_INVALID_DST_REG              );
  TEST( FD_VM_ERR_INF_LOOP                     );
  TEST( FD_VM_ERR_JMP_OUT_OF_BOUNDS            );
  TEST( FD_VM_ERR_JMP_TO_ADDL_IMM              );
  TEST( FD_VM_ERR_INVALID_END_IMM              );
  TEST( FD_VM_ERR_INCOMPLETE_LDQ               );
  TEST( FD_VM_ERR_LDQ_NO_ADDL_IMM              );
  TEST( FD_VM_ERR_NO_SUCH_EXT_CALL             );
# undef TEST

#if 0 /* FIXME: MOVE COVERAGE TO VM */
  FD_LOG_NOTICE(( "Testing fd_vm_log" ));

  FD_TEST( fd_vm_log_collector_flush( lc )==lc );

  uchar const * lc_buf = fd_vm_log_collector_buf( lc ); FD_TEST( lc_buf );
  FD_TEST( fd_vm_log_collector_buf_max  ( lc )==FD_VM_LOG_MAX );
  FD_TEST( fd_vm_log_collector_buf_used ( lc )==0UL                         );
  FD_TEST( fd_vm_log_collector_buf_avail( lc )==FD_VM_LOG_MAX );

  ulong lc_mirror_used  = 0UL;
  ulong lc_mirror_avail = FD_VM_LOG_MAX;

  for( ulong trial=0UL; trial<100000UL; trial++ ) {

    for( ulong iter=0UL; iter<10UL; iter++ ) {

      /* Make a random message */
      uchar msg[ FD_VM_LOG_MAX*2UL ];
      ulong msg_sz = fd_rng_ulong_roll( rng, FD_VM_LOG_MAX*2UL );
      uchar byte   = fd_rng_uchar( rng );
      for( ulong msg_off=0UL; msg_off<msg_sz; msg_off++ ) msg[ msg_off ] = byte++;

      /* Append it to the mirror */
      ulong cpy_sz = fd_ulong_min( msg_sz, lc_mirror_avail );
      if( FD_LIKELY( cpy_sz ) ) memcpy( lc_mirror + lc_mirror_used, msg, cpy_sz );
      lc_mirror_used  += cpy_sz;
      lc_mirror_avail -= cpy_sz;

      /* Append it to the log collector */
      FD_TEST( fd_vm_log_collector_append( lc, msg, msg_sz )==lc );

      /* Test append was successful */
      FD_TEST( fd_vm_log_collector_buf      ( lc )==lc_buf          );
      FD_TEST( fd_vm_log_collector_buf_max  ( lc )==FD_VM_LOG_MAX   );
      FD_TEST( fd_vm_log_collector_buf_used ( lc )==lc_mirror_used  );
      FD_TEST( fd_vm_log_collector_buf_avail( lc )==lc_mirror_avail );
      FD_TEST( !memcmp( lc_buf, lc_mirror, lc_mirror_used )         );
    }

    /* Get ready for next trial */

    if( fd_rng_uint( rng ) & 1U ) FD_TEST( fd_vm_log_collector_flush( lc )==lc );
    else {
      FD_TEST( fd_vm_log_collector_wipe( lc )==lc );
      for( ulong lc_off=0UL; lc_off<FD_VM_LOG_MAX; lc_off++ ) FD_TEST( !lc_buf[ lc_off ] );
    }
    FD_TEST( fd_vm_log_collector_buf_max  ( lc )==FD_VM_LOG_MAX );
    FD_TEST( fd_vm_log_collector_buf_used ( lc )==0UL           );
    FD_TEST( fd_vm_log_collector_buf_avail( lc )==FD_VM_LOG_MAX );

    lc_mirror_used = 0UL;
    lc_mirror_avail = FD_VM_LOG_MAX;
  }
#endif

  FD_LOG_NOTICE(( "Testing fd_vm_disasm" ));

  /* FIXME: TEST WITH SYSCALLS TOO */

  char  out[128]; out[0] = '\0';
  ulong out_max = 128UL;
  ulong out_len = 0UL;

  ulong text[2];
  text[0] = fd_rng_ulong( rng );
  text[1] = fd_rng_ulong( rng );

  FD_TEST( fd_vm_disasm_instr( NULL, 1UL, 0UL, NULL, out,  out_max, &out_len )==FD_VM_ERR_INVAL ); /* NULL instr    */
  FD_TEST( fd_vm_disasm_instr( text, 0UL, 0UL, NULL, out,  out_max, &out_len )==FD_VM_ERR_INVAL ); /* zero cnt      */
  FD_TEST( fd_vm_disasm_instr( text, 1UL, 0UL, NULL, NULL, out_max, &out_len )==FD_VM_ERR_INVAL ); /* NULL out      */
  FD_TEST( fd_vm_disasm_instr( text, 1UL, 0UL, NULL, out,  0UL,     &out_len )==FD_VM_ERR_INVAL ); /* zero out_max  */
  FD_TEST( fd_vm_disasm_instr( text, 1UL, 0UL, NULL, out,  out_max, NULL     )==FD_VM_ERR_INVAL ); /* NULL _out_len */
  out_len = out_max;
  FD_TEST( fd_vm_disasm_instr( text, 1UL, 0UL, NULL, out,  out_max, &out_len )==FD_VM_ERR_INVAL ); /* bad _out_len  */

  for( ulong iter=0UL; iter<10000000UL; iter++ ) {
    text[0] = fd_rng_ulong( rng );
    text[1] = fd_rng_ulong( rng );

    fd_sbpf_instr_t instr = fd_sbpf_instr( text[0] );
    instr.imm = fd_pchash( fd_rng_uint( rng )>>11 ); /* Use the pchash of a 21-bit random number to execise some esoteric code paths */
    text[0] = fd_sbpf_ulong( instr );

    int   mw  = (instr.opcode.any.op_class==FD_SBPF_OPCODE_CLASS_LD);
    int   tr  = !(fd_rng_uint( rng ) & 0xffU);
    ulong cnt = (mw & !tr) ? 2UL : 1UL;
    ulong pc  = fd_rng_ulong( rng ) & 0xffffUL;

    out[0]  = '\0';
    out_len = 0UL;
    int err = fd_vm_disasm_instr( text, cnt, pc, NULL, out, out_max, &out_len );

    if( out_len ) FD_TEST( !err );
    else          FD_TEST(  err );
    FD_TEST( out_len<out_max        );
    FD_TEST( out[out_len]=='\0'     );
    FD_TEST( strlen( out )==out_len );

    if( 0 ) FD_LOG_NOTICE(( "%016lx %016lx (cnt %lu pc %04lx mw %i tr %i) -> %-40s (%i-%s)",
                            text[0], text[1], cnt, pc, mw, tr, out, err, fd_vm_strerror( err ) ));
  }

  FD_TEST( fd_vm_disasm_program( NULL, 2UL, NULL, out,  out_max, &out_len )==FD_VM_ERR_INVAL ); /* NULL instr w/ non-zero sz */
  FD_TEST( fd_vm_disasm_program( text, 2UL, NULL, NULL, out_max, &out_len )==FD_VM_ERR_INVAL ); /* NULL out      */
  FD_TEST( fd_vm_disasm_program( text, 2UL, NULL, out,  0UL,     &out_len )==FD_VM_ERR_INVAL ); /* zero out_max  */
  FD_TEST( fd_vm_disasm_program( text, 2UL, NULL, out,  out_max, NULL     )==FD_VM_ERR_INVAL ); /* NULL _out_len */
  out_len = out_max;
  FD_TEST( fd_vm_disasm_program( text, 2UL, NULL, out,  out_max, &out_len )==FD_VM_ERR_INVAL ); /* bad _out_len  */

  /* FIXME: more coverage of fd_vm_disasm_program */

  FD_LOG_NOTICE(( "Testing fd_vm_trace (--event-max %lu --event-data-max %lu)", event_max, event_data_max ));

  /* Test trace constructors */

  ulong align = fd_vm_trace_align();
  FD_TEST( align==8UL );

  FD_TEST( !fd_vm_trace_footprint( ULONG_MAX, event_data_max ) ); /* bad event_max */
  FD_TEST( !fd_vm_trace_footprint( event_max, ULONG_MAX      ) ); /* bad event_data_max */
  ulong footprint = fd_vm_trace_footprint( event_max, event_data_max );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  if( FD_UNLIKELY( footprint>2048UL ) ) FD_LOG_ERR(( "update unit test to support this large trace" ));

  uchar shmem[ 2048 ] __attribute__((aligned(8)));

  FD_TEST( !fd_vm_trace_new( NULL,        event_max, event_data_max ) ); /* NULL shmem */
  FD_TEST( !fd_vm_trace_new( (void *)1UL, event_max, event_data_max ) ); /* misaligned shmem */
  FD_TEST( !fd_vm_trace_new( shmem,       ULONG_MAX, event_data_max ) ); /* bad event_max */
  FD_TEST( !fd_vm_trace_new( shmem,       event_max, ULONG_MAX      ) ); /* bad event_data_max */
  void * _trace = fd_vm_trace_new( shmem, event_max, event_data_max ); FD_TEST( _trace );

  FD_TEST( !fd_vm_trace_join( NULL        ) ); /* NULL       _trace */
  FD_TEST( !fd_vm_trace_join( (void *)1UL ) ); /* misaligned _trace */
  /* not a trace below */
  fd_vm_trace_t * trace = fd_vm_trace_join( _trace ); FD_TEST( trace );

  /* Test trace accessors */

  FD_TEST( fd_vm_trace_event         ( trace )                 );
  FD_TEST( fd_vm_trace_event_sz      ( trace )==0UL            );
  FD_TEST( fd_vm_trace_event_max     ( trace )==event_max      );
  FD_TEST( fd_vm_trace_event_data_max( trace )==event_data_max );

  /* Test trace info */

  for( int type=0; type<3; type++ )
    for( int valid=0; valid<2; valid++ ) {
      ulong info = fd_vm_trace_event_info( type, valid );
      FD_TEST( fd_vm_trace_event_info_type ( info )==type  );
      FD_TEST( fd_vm_trace_event_info_valid( info )==valid );
    }

  /* Test tracing */

  ulong reg[ 3UL+FD_VM_REG_CNT ];
  for( ulong i=0UL; i<3UL+FD_VM_REG_CNT; i++ ) reg[i] = fd_rng_ulong( rng );
  text[0] = fd_rng_ulong( rng );
  text[1] = fd_rng_ulong( rng );

  FD_TEST( fd_vm_trace_event_exe( NULL, reg[0UL] & 0xffffUL, reg[1UL] & 0xffffUL, reg[2UL], reg+3UL, text, 2UL )==FD_VM_ERR_INVAL );
  FD_TEST( fd_vm_trace_event_mem( NULL, 1, 2UL, 3UL, reg                                                       )==FD_VM_ERR_INVAL );

  for(;;) {
    uint r = fd_rng_uint( rng );
    int type = (int)(r & 1U); r >>= 1;
    switch( type ) {

    default:
    case 0: { /* exe */
      for( ulong i=0UL; i<3UL+FD_VM_REG_CNT; i++ ) reg[i] = fd_rng_ulong( rng );
      text[0] = fd_rng_ulong( rng );
      text[1] = fd_rng_ulong( rng );
      int err = fd_vm_trace_event_exe( trace, reg[0UL] & 0xffffUL, reg[1UL] & 0xffffUL, reg[2UL], reg+3UL, text, 2UL );
      if( FD_UNLIKELY( err==FD_VM_ERR_FULL ) ) goto vm_trace_done;
      FD_TEST( !err );
      break;
    }

    case 1: { /* mem */
      int   write = (int)  (r &   1U); r >>= 1;
      int   null  = (int)  (r &   1U); r >>= 1;
      uchar byte  = (uchar)(r & 255U); r >>= 8;
      ulong vaddr = fd_rng_ulong( rng );
      ulong sz    = fd_rng_ulong( rng ) & 127UL;
      uchar msg[128];
      for( ulong off=0UL; off<sz; off++ ) msg[off] = (byte++);
      void * data = null ? NULL : msg;

      int err = fd_vm_trace_event_mem( trace, write, vaddr, sz, data );
      if( FD_UNLIKELY( err==FD_VM_ERR_FULL ) ) goto vm_trace_done;
      FD_TEST( !err );
      break;
    }

    }
  }

vm_trace_done:

  /* FIXME: Iterate over the trace manually and verify contents */

  FD_TEST( fd_vm_trace_printf( NULL, NULL )==FD_VM_ERR_INVAL );

  FD_LOG_NOTICE(( "Synthetic trace"));
  FD_TEST( !fd_vm_trace_printf( trace, NULL ) );
  /* FIXME: More fd_vm_trace coverage */

  /* Test destructors */

  FD_TEST( !fd_vm_trace_leave( NULL) );
  FD_TEST( fd_vm_trace_leave( trace )==_trace );

  FD_TEST( !fd_vm_trace_delete( NULL        ) ); /* NULL       _trace */
  FD_TEST( !fd_vm_trace_delete( (void *)1UL ) ); /* misaligned _trace */
  /* not a trace below */

  FD_TEST( fd_vm_trace_delete( _trace )==(void *)shmem );

  FD_TEST( !fd_vm_trace_join  ( _trace ) ); /* not a trace */
  FD_TEST( !fd_vm_trace_delete( _trace ) ); /* not a trace */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
