#include "fd_vm.h"
#include "../../ballet/sbpf/fd_sbpf_instr.h"
#include "../../ballet/sbpf/fd_sbpf_opcodes.h"

ulong
fd_vm_trace_align( void ) {
  return 8UL;
}

ulong
fd_vm_trace_footprint( ulong event_max ) {
  if( FD_UNLIKELY( event_max>(1UL<<60) ) ) return 0UL; /* FIXME: tune these bounds */
  return fd_ulong_align_up( sizeof(fd_vm_trace_t) + event_max, 8UL );
}

void *
fd_vm_trace_new( void * shmem,
                 ulong  event_max ) {
  fd_vm_trace_t * trace = (fd_vm_trace_t *)shmem;

  if( FD_UNLIKELY( !trace ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_vm_trace_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_vm_trace_footprint( event_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad event_max" ));
    return NULL;
  }

  memset( trace, 0, footprint );

  trace->event_max = event_max;
  trace->event_sz  = 0UL;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( trace->magic ) = FD_VM_TRACE_MAGIC;
  FD_COMPILER_MFENCE();

  return trace;
}

fd_vm_trace_t *
fd_vm_trace_join( void * _trace ) {
  fd_vm_trace_t * trace = (fd_vm_trace_t *)_trace;

  if( FD_UNLIKELY( !trace ) ) {
    FD_LOG_WARNING(( "NULL _trace" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)_trace, fd_vm_trace_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned _trace" ));
    return NULL;
  }

  if( FD_UNLIKELY( trace->magic!=FD_VM_TRACE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return trace;
}

void *
fd_vm_trace_leave( fd_vm_trace_t * trace ) {

  if( FD_UNLIKELY( !trace ) ) {
    FD_LOG_WARNING(( "NULL trace" ));
    return NULL;
  }

  return (void *)trace;
}

void *
fd_vm_trace_delete( void * _trace ) {
  fd_vm_trace_t * trace = (fd_vm_trace_t *)_trace;

  if( FD_UNLIKELY( !trace ) ) {
    FD_LOG_WARNING(( "NULL _trace" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)_trace, fd_vm_trace_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned _trace" ));
    return NULL;
  }

  if( FD_UNLIKELY( trace->magic!=FD_VM_TRACE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( trace->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)trace;
}

int
fd_vm_trace_event_exe( fd_vm_trace_t * trace,
                       ulong           pc,
                       ulong           ic,
                       ulong           cu,
                       ulong           reg[ FD_VM_REG_CNT ],
                       ulong const *   text,
                       ulong           text_cnt,
                       ulong           ic_correction,
                       ulong           frame_cnt ) {

  /* Acquire event storage */

  if( FD_UNLIKELY( (!trace) | (!reg) | (!text) | (!text_cnt) ) ) return FD_VM_ERR_INVAL;

  ulong text0     = FD_LOAD( ulong, text );
  int   multiword = (text_cnt>1UL) & (fd_sbpf_instr( text0 ).opcode.any.op_class==FD_SBPF_OPCODE_CLASS_LD);

  ulong event_footprint = sizeof(fd_vm_trace_event_exe_t) - fd_ulong_if( !multiword, 8UL, 0UL );

  ulong event_sz  = trace->event_sz;
  ulong event_rem = trace->event_max - event_sz;
  if( FD_UNLIKELY( event_footprint > event_rem ) ) return FD_VM_ERR_FULL;

  fd_vm_trace_event_exe_t * event = (fd_vm_trace_event_exe_t *)((ulong)(trace+1) + event_sz);

  trace->event_sz = event_sz + event_footprint;

  /* Record the event */

  event->multiword = (ulong)multiword;
  event->pc        = pc;
  event->ic        = ic;
  event->cu        = cu;
  memcpy( event->reg, reg, FD_VM_REG_CNT*sizeof(ulong) );
  event->text[0] = text0;
  event->ic_correction = ic_correction;
  event->frame_cnt = frame_cnt;
  if( FD_UNLIKELY( multiword ) ) event->text[1] = FD_LOAD( ulong, text+1 );

  return FD_VM_SUCCESS;
}



#include <stdio.h>

int
fd_vm_trace_printf( fd_vm_trace_t const *      trace,
                    fd_sbpf_syscalls_t const * syscalls ) {

  if( FD_UNLIKELY( !trace ) ) {
    FD_LOG_WARNING(( "bad input args" ));
    return FD_VM_ERR_INVAL;
  }

  uchar const * ptr = fd_vm_trace_event   ( trace ); /* Note: this point is 8 byte aligned */
  ulong         rem = fd_vm_trace_event_sz( trace );
  while( rem ) {

    if( FD_UNLIKELY( rem < sizeof( fd_vm_trace_event_exe_t ) - 8UL ) ) {
      FD_LOG_WARNING(( "truncated event (exe)" ));
      return FD_VM_ERR_IO;
    }

    fd_vm_trace_event_exe_t const * event = (fd_vm_trace_event_exe_t const *)ptr;

    int   multiword       = (int)event->multiword;
    ulong event_footprint = sizeof( fd_vm_trace_event_exe_t ) - fd_ulong_if( !multiword, 8UL, 0UL );
    if( FD_UNLIKELY( rem < event_footprint ) ) {
      FD_LOG_WARNING(( "truncated event (exe)" ));
      return FD_VM_ERR_IO;
    }

    ulong event_pc = event->pc;

    /* Pretty print the architectural state before the instruction */

    printf( "%5lu [%016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX] %5lu: ",
            event->ic,
            event->reg[ 0], event->reg[ 1], event->reg[ 2], event->reg[ 3],
            event->reg[ 4], event->reg[ 5], event->reg[ 6], event->reg[ 7],
            event->reg[ 8], event->reg[ 9], event->reg[10], event_pc );

    /* Print the instruction */

    ulong out_len = 0UL;
    char  out[128];
    out[0] = '\0';
    int err = fd_vm_disasm_instr( event->text, fd_ulong_if( !multiword, 1UL, 2UL ), event_pc, syscalls, out, 128UL, &out_len );
    if( FD_UNLIKELY( err ) ) printf( "disasm failed (%i-%s)", err, fd_vm_strerror( err ) );
    else                     printf( "%s", out );

    /* Print CUs  */
    printf( " %lu\n", event->cu );
    fflush( stdout );

    ptr += event_footprint;
    rem -= event_footprint;
  }

  return FD_VM_SUCCESS;
}
