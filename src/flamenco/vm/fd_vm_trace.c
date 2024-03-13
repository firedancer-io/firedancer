#include "fd_vm_private.h"

ulong
fd_vm_trace_align( void ) {
  return 8UL;
}

ulong
fd_vm_trace_footprint( ulong event_max,
                       ulong event_data_max ) {
  if( FD_UNLIKELY( (event_max>(1UL<<60)) | (event_data_max>(1UL<<60)) ) ) return 0UL; /* FIXME: tune these bounds */
  return fd_ulong_align_up( sizeof(fd_vm_trace_t) + event_max, 8UL );
}

void *
fd_vm_trace_new( void * shmem,
                 ulong  event_max,
                 ulong  event_data_max ) {
  fd_vm_trace_t * trace = (fd_vm_trace_t *)shmem;

  if( FD_UNLIKELY( !trace ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_vm_trace_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_vm_trace_footprint( event_max, event_data_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad event_max or event_data_max" ));
    return NULL;
  }

  memset( trace, 0, footprint );

  trace->event_max      = event_max;
  trace->event_data_max = event_data_max;
  trace->event_off      = 0UL;

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
                       ulong           reg[ FD_VM_REG_CNT ] ) {

  /* Acquire event storage */

  if( FD_UNLIKELY( !trace ) ) return FD_VM_ERR_INVAL;

  ulong event_off = trace->event_off;
  ulong event_rem = trace->event_max - event_off;

  ulong event_footprint = fd_ulong_align_up( sizeof(fd_vm_trace_event_exe_t), 8UL );

  if( FD_UNLIKELY( event_footprint > event_rem ) ) return FD_VM_ERR_FULL;

  fd_vm_trace_event_exe_t * event = (fd_vm_trace_event_exe_t *)((ulong)(trace+1) + event_off);

  trace->event_off = event_off + event_footprint;

  event->info = fd_vm_trace_event_info( FD_VM_TRACE_EVENT_TYPE_EXE, 0 );
  event->pc   = pc;
  event->ic   = ic;
  event->cu   = cu;
  memcpy( event->reg, reg, FD_VM_REG_CNT*sizeof(ulong) );

  return FD_VM_SUCCESS;
}

int
fd_vm_trace_event_mem( fd_vm_trace_t * trace,
                       int             write,
                       ulong           vaddr,
                       ulong           sz,
                       void *          data ) {

  /* Acquire event storage */

  if( FD_UNLIKELY( !trace ) ) return FD_VM_ERR_INVAL;

  ulong event_off = trace->event_off;
  ulong event_rem = trace->event_max - event_off;

  int   valid           = (!!data) & (!!sz); /* FIXME: ponder sz==0 handling */
  ulong event_data_sz   = fd_ulong_if( valid, fd_ulong_min( sz, trace->event_data_max ), 0UL );
  ulong event_footprint = fd_ulong_align_up( sizeof(fd_vm_trace_event_mem_t) + event_data_sz, 8UL );

  if( FD_UNLIKELY( event_footprint > event_rem ) ) return FD_VM_ERR_FULL;

  fd_vm_trace_event_mem_t * event = (fd_vm_trace_event_mem_t *)((ulong)(trace+1) + event_off);

  trace->event_off = event_off + event_footprint;

  /* Record the event */

  event->info  = fd_vm_trace_event_info( fd_int_if( write, FD_VM_TRACE_EVENT_TYPE_WRITE, FD_VM_TRACE_EVENT_TYPE_READ ), valid );
  event->vaddr = vaddr;
  event->sz    = sz;
  if( FD_LIKELY( valid ) ) memcpy( event+1, data, event_data_sz );

  return FD_VM_SUCCESS;
}

#include <stdio.h>

int
fd_vm_trace_printf( fd_vm_trace_t const *      trace,
                    ulong const *              text,
                    ulong                      text_cnt,
                    fd_sbpf_syscalls_t const * syscalls ) {

  if( FD_UNLIKELY( (!trace) | ((!!text_cnt) & ((!text) | (!syscalls))) ) ) {
    FD_LOG_WARNING(( "bad input args" ));
    return FD_VM_ERR_INVAL;
  }

  ulong data_max = fd_vm_trace_event_data_max( trace );

  uchar const * ptr = fd_vm_trace_event   ( trace ); /* Note: this point is 8 byte aligned */
  ulong         rem = fd_vm_trace_event_sz( trace );
  while( rem ) {

    /* Read the event info */

    if( FD_UNLIKELY( rem<7UL ) ) {
      FD_LOG_WARNING(( "truncated event (info)" ));
      return FD_VM_ERR_IO;
    }

    ulong info = *(ulong *)ptr; /* Note: this point is 8 byte aligned */

    ulong event_footprint;

    int event_type = fd_vm_trace_event_info_type( info );
    switch( event_type ) {

    case FD_VM_TRACE_EVENT_TYPE_EXE: {

      event_footprint = sizeof( fd_vm_trace_event_exe_t );
      if( FD_UNLIKELY( rem < event_footprint ) ) {
        FD_LOG_WARNING(( "truncated event (exe)" ));
        return FD_VM_ERR_IO;
      }

      fd_vm_trace_event_exe_t * event = (fd_vm_trace_event_exe_t *)ptr;

      ulong event_pc = event->pc;

      /* Pretty print the architectural state before the instruction */
      /* FIXME: PRINT CUS? */
      /* FIXME: THIS OFFSET IS FOR TESTING ONLY (DOUBLE FIXME) */

      printf( "%5lu [%016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX, %016lX] %5lu: ",
              event->ic,
              event->reg[ 0], event->reg[ 1], event->reg[ 2], event->reg[ 3],
              event->reg[ 4], event->reg[ 5], event->reg[ 6], event->reg[ 7],
              event->reg[ 8], event->reg[ 9], event->reg[10], event_pc + 29UL );

      /* Print the instruction */

      if( FD_UNLIKELY( !text_cnt ) ) printf( "-\n" );
      else {
        if( FD_UNLIKELY( event_pc>=text_cnt ) ) printf( " bad pc\n" );
        ulong out_len = 0UL;
        char  out[128];
        out[0] = '\0';
        int err = fd_vm_disasm_instr( text+event_pc, text_cnt-event_pc, event_pc, syscalls, out, 128UL, &out_len );
        if( FD_UNLIKELY( err ) ) printf( "disasm failed (%i-%s)\n", err, fd_vm_strerror( err ) );
        printf( "%s\n", out );
      }

      break;
    }

    case FD_VM_TRACE_EVENT_TYPE_READ:
    case FD_VM_TRACE_EVENT_TYPE_WRITE: {

      event_footprint = sizeof(fd_vm_trace_event_mem_t);
      if( FD_UNLIKELY( rem < event_footprint ) ) {
        FD_LOG_WARNING(( "truncated event (mem)" ));
        return FD_VM_ERR_IO;
      }

      fd_vm_trace_event_mem_t * event = (fd_vm_trace_event_mem_t *)ptr;

      int   valid    = fd_vm_trace_event_info_valid( info );
      ulong event_sz = event->sz;
      ulong data_sz  = fd_ulong_if( valid, fd_ulong_min( event_sz, data_max ), 0UL );

      event_footprint = fd_ulong_align_up( event_footprint + data_sz, 8UL );
      if( FD_UNLIKELY( rem < event_footprint ) ) {
        FD_LOG_WARNING(( "truncated event (data)" ));
        return FD_VM_ERR_IO;
      }

      uchar * data = (uchar *)(event+1);

      ulong prev_ic = 0UL; /* FIXME: there was some commented out code originally to find the ic that previously modified */

      printf( "        %s: vm_addr: 0x%016lX, sz: %8lu, prev_ic: %8lu, data: ",
              event_type==FD_VM_TRACE_EVENT_TYPE_READ ? "R" : "W", event->vaddr, event_sz, prev_ic );

      char buf[ 1024UL + 6UL*2048UL ]; /* 1KiB for overhead + 6 bytes for every byte of event_data_max */

      char * p = fd_cstr_init( buf );
      if( !valid ) p = fd_cstr_append_char( p, '-' );
      else {
        for( ulong data_off=0UL; data_off<data_sz; data_off++ ) {
          if( FD_UNLIKELY( (data_off & 0xfUL)==0UL ) ) p = fd_cstr_append_printf( p, "\n                0x%04lX:", data_off );
          if( FD_UNLIKELY( (data_off & 0xfUL)==8UL ) ) p = fd_cstr_append_char( p, ' ' );
          p = fd_cstr_append_printf( p, " %02X", (uint)data[ data_off ] );
        }
        if( FD_UNLIKELY( data_sz < event_sz ) )
          p = fd_cstr_append_printf( p, "\n                ... omitted %lu bytes ...", event_sz - data_sz );
      }
      p = fd_cstr_append_char( p, '\n' );
      fd_cstr_fini( p );

      printf( "%s", buf );
      break;
    }

    default: {
      FD_LOG_WARNING(( "unexpected event type" ));
      return FD_VM_ERR_IO;
    }

    }

    ptr += event_footprint;
    rem -= event_footprint;
  }

  return FD_VM_SUCCESS;
}
