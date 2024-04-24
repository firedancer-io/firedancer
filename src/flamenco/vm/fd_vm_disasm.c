#include "fd_vm_base.h"
#include <stdarg.h>

/* fd_vm_disasm_printf appends to the *_len string in the max byte
   buffer buf the printf of the remaining args.  On input, assumes *_len
   is strlen(buf) and *_len is in [0,max).  On output, even on error
   cases, the leading string in buf will be unchanged, *len will be
   strlen(buf) and *len will be [*len_as_it_was_on_input,max).

   Returns:

   FD_VM_SUCCESS - success.  buf and *len updated.

   FD_VM_ERR_FULL - not enough room in buf to hold result.  As many
   bytes as possible were written to buf and *len==max-1 on return.

   FD_VM_ERR_IO - printf format parse error.  buf and *len unchanged but
   trailing bytes of buf might have been clobbered. */

/* FIXME: REWORK API TO USE FD_CSTR_PRINTF HERE?  (OR CONSIDER ADDING
   FD_VM_DISASM_PRINTF AS A FD_CSTR API) */

static int
fd_vm_disasm_printf( char *       buf,
                     ulong        max,
                     ulong *      _len,
                     char const * fmt, ... ) __attribute__((format(printf,4,5)));

static int
fd_vm_disasm_printf( char *       buf,
                     ulong        max,
                     ulong *      _len,
                     char const * fmt, ... ) {
  ulong len = *_len;     /* In [0,max) */
  ulong rem = max - len; /* In (0,max] */

  va_list ap;
  va_start( ap, fmt );
  int ret = vsnprintf( buf + len, rem, fmt, ap );
  va_end( ap );

  if( FD_UNLIKELY( ret<0 ) ) { /* Parse error */
    buf[len] = '\0'; /* Guarantee '\0' termination */
    return FD_VM_ERR_IO;
  }

  ulong append_len = (ulong)ret; /* Guaranteed safe */

  if( FD_UNLIKELY( append_len>=rem ) ) { /* Truncated output */
    buf[max-1UL] = '\0'; /* Guarantee '\0' termination */
    *_len = max-1UL;
    return FD_VM_ERR_FULL;
  }

  *_len = len + append_len;
  return FD_VM_SUCCESS;
}

/* OUT_PRINTF is a convenience macro to do boilerplate error trapping
   on fd_vm_disasm_printf. */

#define OUT_PRINTF( ... ) do {                                             \
    int _err = fd_vm_disasm_printf( out, out_max, _out_len, __VA_ARGS__ ); \
    if( FD_UNLIKELY( _err ) ) return _err;                                 \
  } while(0)

/* fd_vm_disasm_instr_* are pretty printers for single word instructions.
   They do not validate their input arguments.  Return out, out_max,
   _out_len and return error code have the same interpretation as their
   public facing wrappers. */

static int
fd_vm_disasm_instr_alu( fd_sbpf_instr_t instr,
                        char const *    suffix,
                        char *          out,
                        ulong           out_max,
                        ulong *         _out_len ) {

  char * op_name;
  switch( instr.opcode.normal.op_mode ) {
  case FD_SBPF_OPCODE_ALU_OP_MODE_ADD:  op_name = "add";  break;
  case FD_SBPF_OPCODE_ALU_OP_MODE_SUB:  op_name = "sub";  break;
  case FD_SBPF_OPCODE_ALU_OP_MODE_MUL:  op_name = "mul";  break;
  case FD_SBPF_OPCODE_ALU_OP_MODE_DIV:  op_name = "div";  break;
  case FD_SBPF_OPCODE_ALU_OP_MODE_OR:   op_name = "or";   break;
  case FD_SBPF_OPCODE_ALU_OP_MODE_AND:  op_name = "and";  break;
  case FD_SBPF_OPCODE_ALU_OP_MODE_LSH:  op_name = "lsh";  break;
  case FD_SBPF_OPCODE_ALU_OP_MODE_RSH:  op_name = "rsh";  break;
  case FD_SBPF_OPCODE_ALU_OP_MODE_NEG:  op_name = "neg";  break;
  case FD_SBPF_OPCODE_ALU_OP_MODE_MOD:  op_name = "mod";  break;
  case FD_SBPF_OPCODE_ALU_OP_MODE_XOR:  op_name = "xor";  break;
  case FD_SBPF_OPCODE_ALU_OP_MODE_MOV:  op_name = "mov";  break;
  case FD_SBPF_OPCODE_ALU_OP_MODE_ARSH: op_name = "arsh"; break;
  case FD_SBPF_OPCODE_ALU_OP_MODE_END:  op_name = "end";  break;
  default: return FD_VM_ERR_INVAL;
  }

  if( FD_UNLIKELY( instr.opcode.normal.op_mode==FD_SBPF_OPCODE_ALU_OP_MODE_NEG ) ) {
    OUT_PRINTF( "%s%s r%d", op_name, suffix, instr.dst_reg );
    return FD_VM_SUCCESS;
  }

  switch( instr.opcode.normal.op_src ) {
  case FD_SBPF_OPCODE_SOURCE_MODE_IMM:
    OUT_PRINTF( "%s%s r%d, %d",  op_name, suffix, instr.dst_reg, instr.imm     );
    return FD_VM_SUCCESS;
  case FD_SBPF_OPCODE_SOURCE_MODE_REG:
    OUT_PRINTF( "%s%s r%d, r%d", op_name, suffix, instr.dst_reg, instr.src_reg );
    return FD_VM_SUCCESS;
  default: break;
  }

  return FD_VM_ERR_INVAL;
}

static int
fd_vm_disasm_instr_jmp( fd_sbpf_instr_t            instr,
                        ulong                      pc,
                        char const *               suffix,
                        fd_sbpf_syscalls_t const * syscalls,
                        char *                     out,
                        ulong                      out_max,
                        ulong *                    _out_len ) {

  char * op_name;
  switch( instr.opcode.normal.op_mode ) {
  case FD_SBPF_OPCODE_JMP_OP_MODE_JA:   op_name = "ja";   break;
  case FD_SBPF_OPCODE_JMP_OP_MODE_JEQ:  op_name = "jeq";  break;
  case FD_SBPF_OPCODE_JMP_OP_MODE_JGT:  op_name = "jgt";  break;
  case FD_SBPF_OPCODE_JMP_OP_MODE_JGE:  op_name = "jge";  break;
  case FD_SBPF_OPCODE_JMP_OP_MODE_JSET: op_name = "jset"; break;
  case FD_SBPF_OPCODE_JMP_OP_MODE_JNE:  op_name = "jne";  break;
  case FD_SBPF_OPCODE_JMP_OP_MODE_JSGT: op_name = "jsgt"; break;
  case FD_SBPF_OPCODE_JMP_OP_MODE_JSGE: op_name = "jsge"; break;
  case FD_SBPF_OPCODE_JMP_OP_MODE_CALL: op_name = "call"; break;
  case FD_SBPF_OPCODE_JMP_OP_MODE_EXIT: op_name = "exit"; break;
  case FD_SBPF_OPCODE_JMP_OP_MODE_JLT:  op_name = "jlt";  break;
  case FD_SBPF_OPCODE_JMP_OP_MODE_JLE:  op_name = "jle";  break;
  case FD_SBPF_OPCODE_JMP_OP_MODE_JSLT: op_name = "jslt"; break;
  case FD_SBPF_OPCODE_JMP_OP_MODE_JSLE: op_name = "jsle"; break;
  default: return FD_VM_ERR_INVAL;
  }

  if( FD_UNLIKELY( instr.opcode.normal.op_mode==FD_SBPF_OPCODE_JMP_OP_MODE_CALL ) ) {
    switch ( instr.opcode.normal.op_src ) {
    case FD_SBPF_OPCODE_SOURCE_MODE_IMM: {
      fd_sbpf_syscalls_t const * syscall = fd_sbpf_syscalls_query( (fd_sbpf_syscalls_t *)syscalls, instr.imm, NULL ); /* FIXME: CONST CORRECT IN SYSCALLS_QUERY */
      if( syscall ) {
        char const * name = syscall->name;
        if( name ) OUT_PRINTF( "syscall%s %s",     suffix, name      );
        else       OUT_PRINTF( "syscall%s 0x%08x", suffix, instr.imm );
      } else {
        uint pc = fd_pchash_inverse( instr.imm );
        if( pc<(10<<17) ) OUT_PRINTF( "%s%s function_%u",  op_name, suffix, pc        ); /* FIXME: hardcoded constant */
        else              OUT_PRINTF( "%s%s function_%#x", op_name, suffix, instr.imm );
      }
      return FD_VM_SUCCESS;
    }
    case FD_SBPF_OPCODE_SOURCE_MODE_REG:
      OUT_PRINTF( "%sx%s r%d", op_name, suffix, instr.imm );
      return FD_VM_SUCCESS;
    default: break;
    }
    return FD_VM_ERR_INVAL;
  }

  if( FD_UNLIKELY( instr.opcode.normal.op_mode==FD_SBPF_OPCODE_JMP_OP_MODE_EXIT ) ) {
    OUT_PRINTF( "%s%s", op_name, suffix );
    return FD_VM_SUCCESS;
  }

  if( FD_UNLIKELY( instr.opcode.normal.op_mode==FD_SBPF_OPCODE_JMP_OP_MODE_JA ) ) {
    OUT_PRINTF( "%s%s lbb_%ld", op_name, suffix, (long)pc+(long)instr.offset+1L );
    return FD_VM_SUCCESS;
  }

  switch( instr.opcode.normal.op_src ) {
  case FD_SBPF_OPCODE_SOURCE_MODE_IMM:
    OUT_PRINTF( "%s%s r%d, %d, lbb_%ld",  op_name, suffix, instr.dst_reg, instr.imm,     (long)pc+(long)instr.offset+1L );
    return FD_VM_SUCCESS;
  case FD_SBPF_OPCODE_SOURCE_MODE_REG:
    OUT_PRINTF( "%s%s r%d, r%d, lbb_%ld", op_name, suffix, instr.dst_reg, instr.src_reg, (long)pc+(long)instr.offset+1L );
    return FD_VM_SUCCESS;
    break;
  default: break;
  }

  return FD_VM_ERR_INVAL;
}

static int
fd_vm_disasm_instr_ldx( fd_sbpf_instr_t instr,
                        char *          out,
                        ulong           out_max,
                        ulong *         _out_len ) {

  char * op_name;
  switch( instr.opcode.mem.op_size ) {
  case FD_SBPF_OPCODE_SIZE_MODE_WORD: op_name = "ldxw";  break;
  case FD_SBPF_OPCODE_SIZE_MODE_HALF: op_name = "ldxh";  break;
  case FD_SBPF_OPCODE_SIZE_MODE_BYTE: op_name = "ldxb";  break;
  case FD_SBPF_OPCODE_SIZE_MODE_DOUB: op_name = "ldxdw"; break;
  default: return FD_VM_ERR_INVAL;
  }

  if( instr.offset<0 ) OUT_PRINTF( "%s r%d, [r%d-0x%x]", op_name, instr.dst_reg, instr.src_reg, -instr.offset );
  else                 OUT_PRINTF( "%s r%d, [r%d+0x%x]", op_name, instr.dst_reg, instr.src_reg,  instr.offset );
  return FD_VM_SUCCESS;
}

static int
fd_vm_disasm_instr_stx( fd_sbpf_instr_t instr,
                        char *          out,
                        ulong           out_max,
                        ulong *         _out_len ) {

  char * op_name;
  switch( instr.opcode.mem.op_size ) {
  case FD_SBPF_OPCODE_SIZE_MODE_WORD: op_name = "stxw";  break;
  case FD_SBPF_OPCODE_SIZE_MODE_HALF: op_name = "stxh";  break;
  case FD_SBPF_OPCODE_SIZE_MODE_BYTE: op_name = "stxb";  break;
  case FD_SBPF_OPCODE_SIZE_MODE_DOUB: op_name = "stxdw"; break;
  default: return FD_VM_ERR_INVAL;
  }

  if( instr.offset<0 ) OUT_PRINTF( "%s [r%d-0x%x], r%d", op_name, instr.dst_reg, -instr.offset, instr.src_reg );
  else                 OUT_PRINTF( "%s [r%d+0x%x], r%d", op_name, instr.dst_reg,  instr.offset, instr.src_reg );
  return FD_VM_SUCCESS;
}

int
fd_vm_disasm_instr( fd_sbpf_instr_t const *    instr,
                    ulong                      instr_cnt,
                    ulong                      pc,
                    fd_sbpf_syscalls_t const * syscalls,
                    char *                     out,
                    ulong                      out_max,
                    ulong *                    _out_len ) {

  if( FD_UNLIKELY( (!instr) | (!instr_cnt) | (!syscalls) | (!out) | (!out_max) | (!_out_len) ) ) return FD_VM_ERR_INVAL;
  if( FD_UNLIKELY( (*_out_len)>=out_max ) ) return FD_VM_ERR_INVAL;

  switch( instr->opcode.any.op_class ) {
  case FD_SBPF_OPCODE_CLASS_LD:
    if( FD_UNLIKELY( instr_cnt<2UL ) ) return FD_VM_ERR_INVAL;
    OUT_PRINTF( "lddw r%d, 0x%lx", instr->dst_reg, (ulong)((ulong)instr[0].imm | (ulong)((ulong)instr[1].imm << 32UL)) );
    return FD_VM_SUCCESS;
  case FD_SBPF_OPCODE_CLASS_LDX:   return fd_vm_disasm_instr_ldx( *instr,                     out, out_max, _out_len);
  case FD_SBPF_OPCODE_CLASS_ST:    return FD_VM_SUCCESS; /* FIXME: HMMM? */
  case FD_SBPF_OPCODE_CLASS_STX:   return fd_vm_disasm_instr_stx( *instr,                     out, out_max, _out_len );
  case FD_SBPF_OPCODE_CLASS_ALU:   return fd_vm_disasm_instr_alu( *instr, "",                 out, out_max, _out_len );
  case FD_SBPF_OPCODE_CLASS_JMP:   return fd_vm_disasm_instr_jmp( *instr, pc, "",   syscalls, out, out_max, _out_len );
  case FD_SBPF_OPCODE_CLASS_JMP32: return fd_vm_disasm_instr_jmp( *instr, pc, "32", syscalls, out, out_max, _out_len );
  case FD_SBPF_OPCODE_CLASS_ALU64: return fd_vm_disasm_instr_alu( *instr, "64",               out, out_max, _out_len );
  default: break;
  }
  return FD_VM_ERR_INVAL;
}

int
fd_vm_disasm_program( fd_sbpf_instr_t const *    program,
                      ulong                      program_cnt,
                      fd_sbpf_syscalls_t const * syscalls,
                      char *                     out,
                      ulong                      out_max,
                      ulong *                    _out_len ) {

  if( FD_UNLIKELY( ((!program) & (!!program_cnt)) | (!syscalls) || (!out) | (!out_max) | (!_out_len) ) ) return FD_VM_ERR_INVAL;
  if( FD_UNLIKELY( (*_out_len)>=out_max ) ) return FD_VM_ERR_INVAL;

  /* Construct the mapping of pc to labels and functions.  FIXME: This
     is currently not an algo efficient implementation. */

  ulong func_cnt  = 0UL;
  ulong label_cnt = 0UL;
  for( ulong i=0UL; i<program_cnt; i++ ) {
    fd_sbpf_instr_t instr = program[i];
    if     ( instr.opcode.raw==FD_SBPF_OP_CALL_IMM ) func_cnt++;
    else if( instr.opcode.raw==FD_SBPF_OP_EXIT     ) func_cnt++;
    else if( instr.opcode.raw==FD_SBPF_OP_CALL_REG ) continue;
    else if( ( (instr.opcode.any.op_class==FD_SBPF_OPCODE_CLASS_JMP  ) |
               (instr.opcode.any.op_class==FD_SBPF_OPCODE_CLASS_JMP32) ) ) label_cnt++;
  }

  if( FD_UNLIKELY( (func_cnt>65536UL) | (label_cnt>65536UL) ) ) return FD_VM_ERR_INVAL; /* FIXME: err code? */

  ulong label_pc[ 65536 ];
  ulong func_pc [ 65536 ];

  for( ulong i=0UL; i<program_cnt; i++ ) {
    fd_sbpf_instr_t instr = program[i];
    if     ( instr.opcode.raw==FD_SBPF_OP_CALL_IMM ) func_pc[ func_cnt++ ] = i + instr.imm + 1UL;
    else if( instr.opcode.raw==FD_SBPF_OP_EXIT     ) func_pc[ func_cnt++ ] = i + instr.imm + 1UL;
    else if( instr.opcode.raw==FD_SBPF_OP_CALL_REG ) continue;
    else if( ( (instr.opcode.any.op_class==FD_SBPF_OPCODE_CLASS_JMP  ) |
               (instr.opcode.any.op_class==FD_SBPF_OPCODE_CLASS_JMP32) ) )
      label_pc[ label_cnt++ ] = (ulong)((long)i + (long)instr.offset + 1L); /* FIXME: hmmm */
  }

  /* Output the program */

  OUT_PRINTF( "function_0:\n" );

  for( ulong i=0UL; i<program_cnt; i++ ) {

    /* Print functions / labels (note: as per logic above, it is not
       possible for pc to have both a label and a function). */

    int found = 0;
    for( ulong j=0UL; j<label_cnt; j++ ) if( label_pc[j]==i ) { found = 1; OUT_PRINTF( "lbb_%lu:\n", i ); break; }
    if( !found ) for( ulong j=0UL; j<func_cnt; j++ ) if( func_pc[j]==i ) { OUT_PRINTF( "\nfunction_%lu:\n", i ); break; }

    /* Print instruction */

    fd_sbpf_instr_t const * instr = &program[i];

    ulong extra_cnt = fd_ulong_if( instr->opcode.any.op_class==FD_SBPF_OPCODE_CLASS_LD, 1UL, 0UL );
    if( FD_UNLIKELY( (i+extra_cnt)>=program_cnt ) ) return FD_VM_ERR_INVAL;

    OUT_PRINTF( "    " );
    int err = fd_vm_disasm_instr( instr, program_cnt-i, i, syscalls, out, out_max, _out_len );
    if( FD_UNLIKELY( err ) ) return err;
    OUT_PRINTF( "\n" );

    i += extra_cnt;

    /* Print any trailing function */
    /* FIXME: Algo efficiency?  Only scan if instr.opcode.raw==JA?  Only
       scan if i+1<program_cnt? */

    found = 0;
    for( ulong j=0UL; j<label_cnt; j++ ) if( label_pc[j]==i+1UL ) { found = 1; break; }
    if( !found && (instr->opcode.raw==FD_SBPF_OP_JA) ) OUT_PRINTF( "\nfunction_%lu:\n", i+1UL );
  }

  return FD_VM_SUCCESS;
}

#undef OUT_PRINTF
