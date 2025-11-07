#ifndef HEADER_fd_src_flamenco_log_collector_fd_log_collector_h
#define HEADER_fd_src_flamenco_log_collector_fd_log_collector_h

#include "fd_log_collector_base.h"
#include "../runtime/context/fd_exec_instr_ctx.h"
#include "../runtime/context/fd_exec_txn_ctx.h"
#include "../vm/fd_vm_base.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/base64/fd_base64.h"
#include <stdio.h>
#include <stdarg.h>

/* Log collector + stable log implementations.
   https://github.com/anza-xyz/agave/blob/v2.0.6/program-runtime/src/log_collector.rs
   https://github.com/anza-xyz/agave/blob/v2.0.6/program-runtime/src/stable_log.rs */

/* INTERNALS
   Internal functions, don't use directly. */

#define FD_EXEC_LITERAL(STR) ("" STR), (sizeof(STR)-1)

/* fd_log_collector_private_push pushes a log (internal, don't use directly).

   This function stores a log msg of size msg_sz, serialized as protobuf.
   For the high-level functionality, see fd_log_collector_msg().

   Internally, each log msg is serialized as a 1 byte tag + 1 or 2 bytes
   msg_sz (variable int < 32768) + msg_sz bytes of the actual msg.

     |  tag   |    msg_sz    |     msg      |
     | 1-byte | 1-or-2 bytes | msg_sz bytes |

   The advantage of this representation is that when we have to store
   txn metadata in blockstore, we don't have to do any conversion for logs,
   just copy the entire buffer. */
static inline void
fd_log_collector_private_push( fd_log_collector_t * log,
                               char const *         msg,
                               ulong                msg_sz ) {
  uchar * buf   = log->buf;
  ulong   buf_sz = log->buf_sz;

  /* Store tag + msg_sz */
  ulong needs_2b  = (msg_sz>0x7F);
  buf[ buf_sz   ] = FD_LOG_COLLECTOR_PROTO_TAG;
  buf[ buf_sz+1 ] = (uchar)( (msg_sz&0x7F) | (needs_2b<<7) );
  buf[ buf_sz+2 ] = (uchar)( (msg_sz>>7) & 0x7F ); /* This gets overwritten if 0 */

  /* Copy msg and update total buf_sz */
  ulong msg_start = buf_sz + 2 + needs_2b;
  fd_memcpy( buf + msg_start, msg, msg_sz );
  log->buf_sz = (ushort)( msg_start + msg_sz );
}

/* fd_log_collector_private_debug prints all logs (internal, don't use directly). */
static inline void
fd_log_collector_private_debug( fd_log_collector_t const * log );

FD_PROTOTYPES_BEGIN

/* LOG COLLECTOR API
   Init, delete... */

/* fd_log_collector_init initializes a log collector. */
static inline void
fd_log_collector_init( fd_log_collector_t * log, int enabled ) {
  log->buf_sz = 0;
  log->log_sz = 0;
  log->warn = 0;
  log->disabled = !enabled;
}

static inline ulong
fd_log_collector_check_and_truncate( fd_log_collector_t * log,
                                     ulong                msg_sz ) {
  ulong bytes_written = fd_ulong_sat_add( log->log_sz, msg_sz );
  int ret = bytes_written >= FD_LOG_COLLECTOR_MAX;
  if( FD_UNLIKELY( ret ) ) {
    if( FD_UNLIKELY( !log->warn ) ) {
      log->warn = 1;
      fd_log_collector_private_push( log, FD_EXEC_LITERAL( "Log truncated" ) );
    }
    return ULONG_MAX;
  }
  return bytes_written;
}

/* fd_log_collector_delete deletes a log collector. */
static inline void
fd_log_collector_delete( fd_log_collector_t const * log ) {
  (void)log;
}

/* LOG COLLECTOR MSG API

   Analogous of Agave's ic_msg!():
   https://github.com/anza-xyz/agave/blob/v2.0.6/program-runtime/src/log_collector.rs

   - fd_log_collector_msg
   - fd_log_collector_msg_literal
   - fd_log_collector_msg_many
   - fd_log_collector_printf_*
*/

/* fd_log_collector_msg logs msg of size msg_sz.
   This is analogous to Agave's ic_msg!() / ic_logger_msg!().

   Logs are not recorded on-chain, and are therefore not
   consensus-critical, however, there exist 3rd party off-chain
   applications that parses logs, and expects logs to be equivalent to
   agave.

   msg is expected to be a valid utf8 string, it is the responsibility
   of the caller to enforce that.  msg doesn't have to be \0 terminated
   and can contain \0 within.  Most logs are cstr, base58/64, so
   they are utf8.  For an example of log from user input, see the
   sol_log_() syscall where we use fd_utf8_verify().

   if msg is a cstr, for compatibility with rust, msg_sz is the msg
   length (not the size of the buffer), and the final \0 should not
   be included in logs.  For literals, use
   fd_log_collector_msg_literal().

   msg_sz==0 is ok, however, it's important to understand that log
   collector is an interface to developers, not exposed to users.
   Users can, for example, log inside BPF programs using msg!(), that
   gets translated to the syscall sol_log_(), that in turn appends
   a log of the form "Program log: ...". So msg_sz, realistically,
   is never 0 nor small.  This is important for our implementation,
   to keep serialization overhead low.

   When msg consists of multiple disjoint buffers, we should use
   fd_log_collector_msg_many(), and implement more variants as
   needed.  The core idea is very simple: we know the total msg_sz,
   we decide if the log needs to be included or truncated, and
   if we include the logs we will copy the actual content
   from multiple places.  This should be the correct and high
   performance way to log.

   For ease of development, and because logs in runtime, vm,
   syscalls, native programs, etc. are what they are, we also
   implemented fd_log_collector_printf_*().  These are
   dangerous to use, especially given the way we serialize
   logs on-the-fly.  Prefer fd_log_collector_msg_* wherever
   possible. */
static inline void
fd_log_collector_msg( fd_exec_instr_ctx_t * ctx,
                      char const *          msg,
                      ulong                 msg_sz ) {
  fd_log_collector_t * log = &ctx->txn_ctx->log_collector;
  if( FD_LIKELY( log->disabled ) ) {
    return;
  }

  ulong bytes_written = fd_log_collector_check_and_truncate( log, msg_sz );
  if( FD_LIKELY( bytes_written < ULONG_MAX ) ) {
    log->log_sz = (ushort)bytes_written;
    fd_log_collector_private_push( log, msg, msg_sz );
  }
}

/* fd_log_collector_msg_literal logs the literal (const cstr) msg,
   handling size.  See fd_log_collector_msg() for details. */
#define fd_log_collector_msg_literal( ctx, log ) fd_log_collector_msg( ctx, FD_EXEC_LITERAL( log ) )

/* fd_log_collector_msg_many logs a msg supplied as many
   buffers.  msg := msg0 | msg1 | ... | msgN

   num_buffers informs the number of (char const * msg, ulong sz) pairs
   in the function call.
   NOTE: you must explicitly pass in ulong values for sz, either by cast
   or with the UL literal. va_args behaves weirdly otherwise */
static inline void
fd_log_collector_msg_many( fd_exec_instr_ctx_t * ctx, int num_buffers, ... ) {
  fd_log_collector_t * log = &ctx->txn_ctx->log_collector;
  if( FD_LIKELY( log->disabled ) ) {
    return;
  }

  va_list args;
  va_start( args, num_buffers );

  /* Calculate the total message size and check for overflow */
  ulong msg_sz = 0;
  for( int i = 0; i < num_buffers; i++ ) {
      va_arg( args, char const * );
      ulong msg_sz_part = va_arg( args, ulong );
      msg_sz = fd_ulong_sat_add( msg_sz, msg_sz_part );
  }
  va_end( args );
  ulong bytes_written = fd_log_collector_check_and_truncate( log, msg_sz );
  if( FD_LIKELY( bytes_written < ULONG_MAX ) ) {
    log->log_sz = (ushort)bytes_written;

    uchar * buf    = log->buf;
    ulong   buf_sz = log->buf_sz;

    /* Store tag + msg_sz */
    ulong needs_2b  = (msg_sz>0x7F);
    buf[ buf_sz ]   = FD_LOG_COLLECTOR_PROTO_TAG;
    buf[ buf_sz+1 ] = (uchar)( (msg_sz&0x7F) | (needs_2b<<7) );
    buf[ buf_sz+2 ] = (uchar)( (msg_sz>>7) & 0x7F ); /* This gets overwritten if 0 */

    /* Copy all messages and update total buf_sz */
    ulong buf_start = buf_sz + 2 + needs_2b;
    ulong offset = buf_start;

    va_start(args, num_buffers);  // Restart argument list traversal
    for (int i = 0; i < num_buffers; i++) {
        char const *msg = va_arg( args, char const * );
        ulong msg_sz_part = va_arg( args, ulong );
        fd_memcpy( buf + offset, msg, msg_sz_part );
        offset += msg_sz_part;
    }
    va_end(args);
    log->buf_sz = (ushort)offset;
  }
}

#define FD_LOG_COLLECTOR_PRINTF_MAX_1B 128
#define FD_LOG_COLLECTOR_PRINTF_MAX_2B 2000
FD_STATIC_ASSERT( 2*FD_LOG_COLLECTOR_PRINTF_MAX_2B <= FD_LOG_COLLECTOR_EXTRA, "Increase FD_LOG_COLLECTOR_EXTRA" );

/* fd_log_collector_printf_dangerous_max_127() logs a message
   supplied as a formatting string with params.

   This is dangerous and should only be used when we can
   guarantee that the total log msg_sz <= 127.

   See also fd_log_collector_printf_dangerous_128_to_2k() for
   larger logs, and see fd_log_collector_program_return() for
   an example on how to deal with msg_sz.

   This implementation uses vsnprintf() to directly write into
   the log buf *before* deciding if the log should be included
   or not.  As a result of vsnprintf() we get msg_sz, and then
   we can decide to actually insert the log or truncate.  Since
   we serialize msg_sz as a variable int, we must guarantee
   that msg_sz <= 127, i.e. fits in 1 byte, otherwise we'd have
   to memmove the log msg. */
__attribute__ ((format (printf, 2, 3)))
static inline void
fd_log_collector_printf_dangerous_max_127( fd_exec_instr_ctx_t * ctx,
                                           char const * fmt, ... ) {
  fd_log_collector_t * log = &ctx->txn_ctx->log_collector;
  if( FD_LIKELY( log->disabled ) ) {
    return;
  }

  uchar * buf    = log->buf;
  ulong   buf_sz = log->buf_sz;

  /* Store the log at buf_sz+2 (1 byte tag + 1 byte msg_sz), and retrieve
     the final msg_sz. */
  va_list ap;
  va_start( ap, fmt );
  int res = vsnprintf( (char *)(buf + buf_sz + 2), FD_LOG_COLLECTOR_PRINTF_MAX_1B, fmt, ap );
  va_end( ap );

  /* We use vsnprintf to protect against oob writes, however, it should
     never truncate.  If truncate happens, it means that we're using
     fd_log_collector_printf_dangerous_max_127(), incorrectly for
     example with a "%s" and an unbound variable (user input, var that's
     not null-terminated cstr, ...).
     We MUST only use fd_log_collector_printf_dangerous_max_127()
     as a convenience method, when we can guarantee that the total
     msg_sz is bound by FD_LOG_COLLECTOR_PRINTF_MAX_1B. */
  FD_TEST_CUSTOM( res>=0 && res<FD_LOG_COLLECTOR_PRINTF_MAX_1B,
    "A transaction log was truncated unexpectedly. Please report to developers." );

  /* Decide if we should include the log or truncate. */
  ulong msg_sz = (ulong)res;
  ulong bytes_written = fd_log_collector_check_and_truncate( log, msg_sz );
  if( FD_LIKELY( bytes_written < ULONG_MAX ) ) {
    /* Insert log: store tag + msg_sz (1 byte) and update buf_sz */
    log->log_sz = (ushort)bytes_written;
    buf[ buf_sz   ] = FD_LOG_COLLECTOR_PROTO_TAG;
    buf[ buf_sz+1 ] = (uchar)( msg_sz & 0x7F );
    log->buf_sz = (ushort)( buf_sz + msg_sz + 2 );
  }
}

/* fd_log_collector_printf_dangerous_128_to_2k() logs a message
   supplied as a formatting string with params.

   This is dangerous and should only be used when we can
   guarantee that the total log 128 <= msg_sz < 2,000.

   This implementation uses vsnprintf() to directly write into
   the log buf *before* deciding if the log should be included
   or not.  As a result of vsnprintf() we get msg_sz, and then
   we can decide to actually insert the log or truncate.  Since
   we serialize msg_sz as a variable int, we must guarantee
   that 128 <= msg_sz < 32758, i.e. fits in 2 byte, otherwise
   we'd have to memmove the log msg.

   Moreover, we need to guarantee that the log buf is big enough
   to fit the log msg.  Hence we further limit msg_sz < 2000. */
__attribute__ ((format (printf, 2, 3)))
static inline void
fd_log_collector_printf_dangerous_128_to_2k( fd_exec_instr_ctx_t * ctx,
                                             char const * fmt, ... ) {
  fd_log_collector_t * log = &ctx->txn_ctx->log_collector;
  if( FD_LIKELY( log->disabled ) ) {
    return;
  }

  uchar * buf    = log->buf;
  ulong   buf_sz = log->buf_sz;

  /* Store the log at buf_sz+3 (1 byte tag + 2 bytes msg_sz), and retrieve
     the final msg_sz. */
  va_list ap;
  va_start( ap, fmt );
  int res = vsnprintf( (char *)(buf + buf_sz + 3), FD_LOG_COLLECTOR_PRINTF_MAX_2B, fmt, ap );
  va_end( ap );
  /* We use vsnprintf to protect against oob writes, however it should
     never truncate.  If truncate happens, it means that we're using
     fd_log_collector_printf_dangerous_max_127(), incorrectly for
     example with a "%s" and an unbound variable (user input, var that's
     not null-terminated cstr, ...).
     We MUST only use fd_log_collector_printf_dangerous_max_128_to_2k()
     as a convenience method, when we can guarantee that the total
     msg_sz is bound by FD_LOG_COLLECTOR_PRINTF_MAX_2B. */
  FD_TEST_CUSTOM( res>=FD_LOG_COLLECTOR_PRINTF_MAX_1B && res<FD_LOG_COLLECTOR_PRINTF_MAX_2B,
    "A transaction log was truncated unexpectedly. Please report to developers." );

  /* Decide if we should include the log or truncate. */
  ulong msg_sz = (ulong)res;
  ulong bytes_written = fd_log_collector_check_and_truncate( log, msg_sz );
  if( FD_LIKELY( bytes_written < ULONG_MAX ) ) {
    /* Insert log: store tag + msg_sz (2 bytes) and update buf_sz */
    log->log_sz = (ushort)bytes_written;
    buf[ buf_sz   ] = FD_LOG_COLLECTOR_PROTO_TAG;
    buf[ buf_sz+1 ] = (uchar)( (msg_sz&0x7F) | (1<<7) );
    buf[ buf_sz+2 ] = (uchar)( (msg_sz>>7) & 0x7F );
    log->buf_sz = (ushort)( buf_sz + msg_sz + 3 );
  }
}

/* fd_log_collector_printf_inefficient_max_512() logs a message
   supplied as a formatting string with params.

   This is inefficient because it uses an external buffer and
   essentially does 2 memcpy instead of 1, however it reduces
   the complexity when msg_sz can be below or above 127, for
   example in many error messages where we have to print 2
   pubkeys. */
__attribute__ ((format (printf, 2, 3)))
static inline void
fd_log_collector_printf_inefficient_max_512( fd_exec_instr_ctx_t * ctx,
                                             char const * fmt, ... ) {
  char msg[ 512 ];

  va_list ap;
  va_start( ap, fmt );
  int msg_sz = vsnprintf( msg, sizeof(msg), fmt, ap );
  va_end( ap );

  FD_TEST_CUSTOM( msg_sz>=0 && (ulong)msg_sz<sizeof(msg),
    "A transaction log was truncated unexpectedly. Please report to developers." );

  fd_log_collector_msg( ctx, msg, (ulong)msg_sz );
}

/* STABLE LOG

   Analogous of Agave's stable_log interface:
   https://github.com/anza-xyz/agave/blob/v2.0.6/program-runtime/src/stable_log.rs

   - program_invoke
   - program_log
   - program_data -- implemented in fd_vm_syscall_sol_log_data()
   - program_return
   - program_success
   - program_failure
   - program_consumed */

/* fd_log_collector_program_invoke logs:
     "Program <ProgramIdBase58> invoke [<n>]"

   This function is called at the beginning of every instruction.
   Other logs (notably success/failure) also write <ProgramIdBase58>,
   so this function precomputes it and stores it inside the instr_ctx. */
static inline void
fd_log_collector_program_invoke( fd_exec_instr_ctx_t * ctx ) {
  if( FD_LIKELY( ctx->txn_ctx->log_collector.disabled ) ) {
    return;
  }

  fd_pubkey_t const * program_id_pubkey = &ctx->txn_ctx->account_keys[ ctx->instr->program_id ];
  /* Cache ctx->program_id_base58 */
  fd_base58_encode_32( program_id_pubkey->uc, NULL, ctx->program_id_base58 );
  /* Max msg_sz: 22 - 4 + 44 + 10 = 72 < 127 => we can use printf */
  fd_log_collector_printf_dangerous_max_127( ctx, "Program %s invoke [%u]", ctx->program_id_base58, ctx->txn_ctx->instr_stack_sz );
}

/* fd_log_collector_program_log logs:
     "Program log: <msg>"

   msg must be a valid utf8 string, it's responsibility of the caller to
   validate that.  This is the implementation underlying the _sol_log()
   syscall. */
static inline void
fd_log_collector_program_log( fd_exec_instr_ctx_t * ctx, char const * msg, ulong msg_sz ) {
  fd_log_collector_msg_many( ctx, 2, "Program log: ", 13UL, msg, msg_sz );
}

/* fd_log_collector_program_return logs:
     "Program return: <ProgramIdBase58> <dataAsBase64>"

   Since return data is at most 1024 bytes, it's base64 representation is
   at most 1368 bytes and msg_sz is known in advance, thus we can use
   fd_log_collector_printf_*.

   TODO: implement based on fd_log_collector_msg_many(). */
static inline void
fd_log_collector_program_return( fd_exec_instr_ctx_t * ctx ) {
  if( FD_LIKELY( ctx->txn_ctx->log_collector.disabled ) ) {
    return;
  }

  /* ctx->txn_ctx->return_data is 1024 bytes max, so its base64 repr
     is at most (1024+2)/3*4 bytes, plus we use 1 byte for \0. */
  char return_base64[ (sizeof(ctx->txn_ctx->return_data.data)+2)/3*4+1 ];
  ulong sz = fd_base64_encode( return_base64, ctx->txn_ctx->return_data.data, ctx->txn_ctx->return_data.len );
  return_base64[ sz ] = 0;
  /* Max msg_sz: 21 - 4 + 44 + 1368 = 1429 < 1500 => we can use printf, but have to handle sz */
  ulong msg_sz = 17 + strlen(ctx->program_id_base58) + sz;
  if( msg_sz<=127 ) {
    fd_log_collector_printf_dangerous_max_127( ctx, "Program return: %s %s", ctx->program_id_base58, return_base64 );
  } else {
    fd_log_collector_printf_dangerous_128_to_2k( ctx, "Program return: %s %s", ctx->program_id_base58, return_base64 );
  }
}

/* fd_log_collector_program_success logs:
     "Program <ProgramIdBase58> success" */
static inline void
fd_log_collector_program_success( fd_exec_instr_ctx_t * ctx ) {
  /* Max msg_sz: 18 - 2 + 44 = 60 < 127 => we can use printf */
  fd_log_collector_printf_dangerous_max_127( ctx, "Program %s success", ctx->program_id_base58 );
}

/* fd_log_collector_program_success logs:
     "Program <ProgramIdBase58> failed: <err>"

   This function handles the logic to log the correct msg, based
   on the type of error (InstructionError, SyscallError...).
   https://github.com/anza-xyz/agave/blob/v2.0.6/program-runtime/src/invoke_context.rs#L535-L549

   The error msg is obtained by external functions, e.g. fd_vm_syscall_strerror(),
   and can be either a valid msg or an empty string.  Empty string represents
   special handling of the error log, for example the syscall panic logs directly
   the result, and therefore can be skipped at this stage. */
static inline void
fd_log_collector_program_failure( fd_exec_instr_ctx_t * ctx ) {
  if( FD_LIKELY( ctx->txn_ctx->log_collector.disabled ) ) {
    return;
  }

  extern char const * fd_vm_ebpf_strerror( int err );
  extern char const * fd_vm_syscall_strerror( int err );
  extern char const * fd_executor_instr_strerror( int err );

  char custom_err[33] = { 0 };
  const char * err = custom_err;
  const fd_exec_txn_ctx_t * txn_ctx = ctx->txn_ctx;
  if( FD_UNLIKELY( txn_ctx->exec_err_kind==FD_EXECUTOR_ERR_KIND_INSTR &&
                   txn_ctx->exec_err==FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) ) {
    /* Max msg_sz = 32 <= 66 */
    snprintf( custom_err, sizeof(custom_err), "custom program error: 0x%x", txn_ctx->custom_err );
  } else if( txn_ctx->exec_err ) {
    switch( txn_ctx->exec_err_kind ) {
      case FD_EXECUTOR_ERR_KIND_SYSCALL:
        err = fd_vm_syscall_strerror( txn_ctx->exec_err );
        break;
      case FD_EXECUTOR_ERR_KIND_INSTR:
        err = fd_executor_instr_strerror( txn_ctx->exec_err );
        break;
      default:
        err = fd_vm_ebpf_strerror( txn_ctx->exec_err );
    }
  }

  /* Skip empty string, this means that the msg has already been logged. */
  if( FD_LIKELY( err[0] ) ) {
    /* Agave logs syscall errors with "Syscall error: " prefix when they cannot be
       downcast to InstructionError.  */
    char err_prefix[ 17+FD_BASE58_ENCODED_32_SZ+15 ]; // 17==strlen("Program  failed: "), 15==strlen("Syscall error: ")
    int needs_prefix = ( txn_ctx->exec_err_kind==FD_EXECUTOR_ERR_KIND_SYSCALL ) &&
                       ( txn_ctx->exec_err==FD_VM_SYSCALL_ERR_UNALIGNED_POINTER ||
                         txn_ctx->exec_err==FD_VM_SYSCALL_ERR_INVALID_LENGTH_MEMORY ||
                         txn_ctx->exec_err==FD_VM_SYSCALL_ERR_TOO_MANY_SIGNERS );
    const char * prefix = needs_prefix ? "Syscall error: " : "";
    int err_prefix_len = sprintf( err_prefix, "Program %s failed: %s", ctx->program_id_base58, prefix );
    if( err_prefix_len > 0 ) {
      /* Equivalent to: "Program %s failed: %s" */
      fd_log_collector_msg_many( ctx, 2, err_prefix, (ulong)err_prefix_len, err, (ulong)strlen(err) );
    }
  }
}

/* fd_log_collector_program_consumed logs:
     "Program <ProgramIdBase58> consumed <consumed> of <tota> compute units" */
static inline void
fd_log_collector_program_consumed( fd_exec_instr_ctx_t * ctx, ulong consumed, ulong total ) {
  /* Max msg_sz: 44 - 8 + 44 + 20 + 20 = 120 < 127 => we can use printf */
  fd_log_collector_printf_dangerous_max_127( ctx, "Program %s consumed %lu of %lu compute units", ctx->program_id_base58, consumed, total );
}

/* DEBUG
   Only used for testing (inefficient but ok). */

static inline ushort
fd_log_collector_debug_get_msg_sz( uchar const ** buf ) {
  uchar msg0 = (*buf)[1];
  uchar msg1 = (*buf)[2]; /* This is never oob */
  int needs_2b = (msg0>0x7F);
  ushort msg_sz = fd_ushort_if( needs_2b, (ushort)(((ushort)(msg1) << 7)|(msg0 & 0x7F)), (ushort)msg0 );
  *buf += 2 + needs_2b;
  return msg_sz;
}

static inline ulong
fd_log_collector_debug_len( fd_log_collector_t const * log ) {
  ulong len = 0;
  for( uchar const * cur = log->buf; cur < log->buf + log->buf_sz; ) {
    ushort cur_sz = fd_log_collector_debug_get_msg_sz( &cur );
    cur += cur_sz;
    ++len;
  }
  return len;
}

static inline uchar const *
fd_log_collector_debug_get( fd_log_collector_t const * log,
                            ulong                      log_num,
                            uchar const **             msg,
                            ulong *                    msg_sz ) {
  uchar const * cur = log->buf;
  ushort cur_sz = 0;

  cur_sz = fd_log_collector_debug_get_msg_sz( &cur );
  while( log_num>0 ) {
    cur += cur_sz;
    cur_sz = fd_log_collector_debug_get_msg_sz( &cur );
    --log_num;
  }
  if( msg )    *msg    = cur;
  if( msg_sz ) *msg_sz = cur_sz;
  return cur;
}

static inline ulong
fd_log_collector_debug_sprintf( fd_log_collector_t const * log,
                                char *                     out,
                                int                        filter_zero ) {
  ulong out_sz = 0;

  ulong pos = 0;
  uchar const * buf = log->buf;
  while( pos < log->buf_sz ) {
    /* Read cur string sz */
    ushort cur_sz = fd_log_collector_debug_get_msg_sz( &buf );

    /* Copy string and add \n.
       Slow version of memcpy that skips \0, because a \0 can be in logs.
       Equivalent to:
       fd_memcpy( out + out_sz, buf, cur_sz ); out_sz += cur_sz; */
    if( filter_zero ) {
      for( ulong i=0; i<cur_sz; i++ ) {
        if( buf[i] ) {
          out[ out_sz++ ] = (char)buf[i];
        }
      }
    } else {
      fd_memcpy( out+out_sz, buf, cur_sz );
      out_sz += cur_sz;
    }
    out[ out_sz++ ] = '\n';

    /* Move to next str */
    buf += cur_sz;
    pos = (ulong)(buf - log->buf);
  }

  /* Remove the last \n, or return empty cstr */
  out_sz = out_sz ? out_sz-1 : 0;
  out[ out_sz ] = '\0';
  return out_sz;
}

static inline void
fd_log_collector_private_debug( fd_log_collector_t const * log ) {
  char out[FD_LOG_COLLECTOR_MAX + FD_LOG_COLLECTOR_EXTRA];
  fd_log_collector_debug_sprintf( log, out, 1 );
  FD_LOG_WARNING(( "\n-----\n%s\n-----", out ));
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_log_collector_fd_log_collector_h */
