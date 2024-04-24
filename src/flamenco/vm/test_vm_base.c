#include "fd_vm_base.h"

/* Verify error codes */

FD_STATIC_ASSERT( FD_VM_SUCCESS                         ==  0, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INVAL                       == -1, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_AGAIN                       == -2, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_UNSUP                       == -3, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_PERM                        == -4, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_FULL                        == -5, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_EMPTY                       == -6, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_IO                          == -7, vm_err );

FD_STATIC_ASSERT( FD_VM_ERR_BUDGET                      == -8, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_ABORT                       == -9, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_PANIC                       ==-10, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_MEM_OVERLAP                 ==-11, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INSTR_ERR                   ==-12, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INVOKE_CONTEXT_BORROW_FAILED==-13, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_RETURN_DATA_TOO_LARGE       ==-14, vm_err );

FD_STATIC_ASSERT( FD_VM_ERR_INVALID_OPCODE              ==-15, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INVALID_SRC_REG             ==-16, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INVALID_DST_REG             ==-17, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INF_LOOP                    ==-18, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_JMP_OUT_OF_BOUNDS           ==-19, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_JMP_TO_ADDL_IMM             ==-20, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INVALID_END_IMM             ==-21, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_INCOMPLETE_LDQ              ==-22, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_LDQ_NO_ADDL_IMM             ==-23, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_NO_SUCH_EXT_CALL            ==-24, vm_err );

FD_STATIC_ASSERT( FD_VM_ERR_MEM_TRANS                   ==-25, vm_err );
FD_STATIC_ASSERT( FD_VM_ERR_BAD_CALL                    ==-26, vm_err );

/* Verify limits */

FD_STATIC_ASSERT( FD_VM_REG_CNT       ==11UL, vm_reg );
FD_STATIC_ASSERT( FD_VM_SHADOW_REG_CNT== 4UL, vm_reg );

FD_STATIC_ASSERT( FD_VM_STACK_FRAME_MAX==64UL,          vm_stack );
FD_STATIC_ASSERT( FD_VM_STACK_FRAME_SZ ==0x1000UL,      vm_stack );
FD_STATIC_ASSERT( FD_VM_STACK_GUARD_SZ ==0x1000UL,      vm_stack );
FD_STATIC_ASSERT( FD_VM_STACK_MAX      ==64UL*0x2000UL, vm_stack );

FD_STATIC_ASSERT( FD_VM_HEAP_DEFAULT== 32UL*1024UL, vm_heap );
FD_STATIC_ASSERT( FD_VM_HEAP_MAX    ==256UL*1024UL, vm_heap );

FD_STATIC_ASSERT( FD_VM_LOG_MAX==10000UL, vm_log );

/* FIXME: COVER MEMORY MAP */
/* FIXME: COVER COMPUTE BUDGET */

FD_STATIC_ASSERT( FD_VM_TRACE_EVENT_TYPE_EXE   ==0, vm_trace );
FD_STATIC_ASSERT( FD_VM_TRACE_EVENT_TYPE_READ  ==1, vm_trace );
FD_STATIC_ASSERT( FD_VM_TRACE_EVENT_TYPE_WRITE ==2, vm_trace );

#if 0 /* FIXME: MOVE TESTING TO VM */
static fd_vm_log_collector_t lc[1];
static uchar lc_mirror[ FD_VM_LOG_MAX ];

static fd_vm_shadow_t shadow[1];
#endif

static fd_sbpf_syscalls_t _syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];

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

  TEST( FD_VM_ERR_BUDGET                       );
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

  TEST( FD_VM_ERR_MEM_TRANS                    );
  TEST( FD_VM_ERR_BAD_CALL                     );
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

  FD_LOG_NOTICE(( "Testing fd_vm_shadow" ));

  FD_TEST( fd_vm_shadow_wipe( shadow )==shadow );
  uchar * _shadow = (uchar *)shadow;
  for( ulong off=0UL; off<sizeof(fd_vm_shadow_t); off++ ) FD_TEST( !_shadow[off] );

  ulong shadow_mirror[ FD_VM_STACK_FRAME_MAX ][ 5 ];
  ulong shadow_mirror_cnt = 0UL;

  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    ulong r[5];

    FD_TEST( fd_vm_shadow_is_empty( shadow )==(shadow_mirror_cnt==0UL)                   );
    FD_TEST( fd_vm_shadow_is_full ( shadow )==(shadow_mirror_cnt>=FD_VM_STACK_FRAME_MAX) );

    int op = (int)(fd_rng_uint( rng ) & 1U);
    switch( op ) {

    default:
    case 0: { /* Push */
      for( ulong i=0UL; i<5UL; i++ ) r[i] = fd_rng_ulong( rng );
      int err = fd_vm_shadow_push( shadow, r[4], r );
      if( FD_UNLIKELY( shadow_mirror_cnt>=FD_VM_STACK_FRAME_MAX ) ) FD_TEST( err==FD_VM_ERR_FULL );
      else {
        FD_TEST( !err );
        memcpy( shadow_mirror[ shadow_mirror_cnt ], r, 5UL*sizeof(ulong) );
        shadow_mirror_cnt++;
      }
      break;
    }

    case 1: { /* Pop */
      ulong r[5];
      int err = fd_vm_shadow_pop( shadow, r+4, r );
      if( FD_UNLIKELY( !shadow_mirror_cnt ) ) FD_TEST( err==FD_VM_ERR_EMPTY );
      else {
        FD_TEST( !err );
        FD_TEST( !memcmp( shadow_mirror[ shadow_mirror_cnt-1UL ], r, 5UL*sizeof(ulong) ) );
        shadow_mirror_cnt--;
      }
      break;
    }

    }
  }
#endif

  FD_LOG_NOTICE(( "Testing fd_vm_disasm" ));

  char  out[128]; out[0] = '\0';
  ulong out_max = 128UL;
  ulong out_len = 0UL;

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) );

  ulong text[2];
  text[0] = fd_rng_ulong( rng );
  text[1] = fd_rng_ulong( rng );

  FD_TEST( fd_vm_disasm_instr( NULL, 1UL, 0UL, syscalls, out,  out_max, &out_len )==FD_VM_ERR_INVAL ); /* NULL instr    */
  FD_TEST( fd_vm_disasm_instr( text, 0UL, 0UL, syscalls, out,  out_max, &out_len )==FD_VM_ERR_INVAL ); /* zero cnt      */
  FD_TEST( fd_vm_disasm_instr( text, 1UL, 0UL, NULL,     out,  out_max, &out_len )==FD_VM_ERR_INVAL ); /* NULL syscalls */
  FD_TEST( fd_vm_disasm_instr( text, 1UL, 0UL, syscalls, NULL, out_max, &out_len )==FD_VM_ERR_INVAL ); /* NULL out      */
  FD_TEST( fd_vm_disasm_instr( text, 1UL, 0UL, syscalls, out,  0UL,     &out_len )==FD_VM_ERR_INVAL ); /* zero out_max  */
  FD_TEST( fd_vm_disasm_instr( text, 1UL, 0UL, syscalls, out,  out_max, NULL     )==FD_VM_ERR_INVAL ); /* NULL _out_len */
  out_len = out_max;
  FD_TEST( fd_vm_disasm_instr( text, 1UL, 0UL, syscalls, out,  out_max, &out_len )==FD_VM_ERR_INVAL ); /* bad _out_len  */

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
    int err = fd_vm_disasm_instr( text, cnt, pc, syscalls, out, out_max, &out_len );

    if( out_len ) FD_TEST( !err );
    else          FD_TEST(  err );
    FD_TEST( out_len<out_max        );
    FD_TEST( out[out_len]=='\0'     );
    FD_TEST( strlen( out )==out_len );

    if( 0 ) FD_LOG_NOTICE(( "%016lx %016lx (cnt %lu pc %04lx mw %i tr %i) -> %-40s (%i-%s)",
                            text[0], text[1], cnt, pc, mw, tr, out, err, fd_vm_strerror( err ) ));
  }

  FD_TEST( fd_vm_disasm_program( NULL, 2UL, syscalls, out,  out_max, &out_len )==FD_VM_ERR_INVAL ); /* NULL instr w/ non-zero sz */
  FD_TEST( fd_vm_disasm_program( text, 2UL, NULL,     out,  out_max, &out_len )==FD_VM_ERR_INVAL ); /* NULL syscalls */
  FD_TEST( fd_vm_disasm_program( text, 2UL, syscalls, NULL, out_max, &out_len )==FD_VM_ERR_INVAL ); /* NULL out      */
  FD_TEST( fd_vm_disasm_program( text, 2UL, syscalls, out,  0UL,     &out_len )==FD_VM_ERR_INVAL ); /* zero out_max  */
  FD_TEST( fd_vm_disasm_program( text, 2UL, syscalls, out,  out_max, NULL     )==FD_VM_ERR_INVAL ); /* NULL _out_len */
  out_len = out_max;
  FD_TEST( fd_vm_disasm_program( text, 2UL, syscalls, out,  out_max, &out_len )==FD_VM_ERR_INVAL ); /* bad _out_len  */

  /* FIXME: more coverage of fd_vm_disasm_program */

  fd_sbpf_syscalls_delete( fd_sbpf_syscalls_leave( syscalls ) );

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
  FD_TEST( fd_vm_trace_event_exe( NULL, reg[0UL] & 0xffffUL, reg[1UL] & 0xffffUL, reg[2UL], reg+3UL )==FD_VM_ERR_INVAL );
  FD_TEST( fd_vm_trace_event_mem( NULL, 1, 2UL, 3UL, reg                                            )==FD_VM_ERR_INVAL );

  for(;;) {
    uint r = fd_rng_uint( rng );
    int type = (int)(r & 1U); r >>= 1;
    switch( type ) {

    default:
    case 0: { /* exe */
      for( ulong i=0UL; i<3UL+FD_VM_REG_CNT; i++ ) reg[i] = fd_rng_ulong( rng );
      int err = fd_vm_trace_event_exe( trace, reg[0UL] & 0xffffUL, reg[1UL] & 0xffffUL, reg[2UL], reg+3UL );
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

  FD_TEST( fd_vm_trace_printf( NULL, NULL, 0UL, NULL )==FD_VM_ERR_INVAL );

  FD_LOG_NOTICE(( "Synthetic trace"));
  FD_TEST( !fd_vm_trace_printf( trace, NULL, 0UL, NULL ) );
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
