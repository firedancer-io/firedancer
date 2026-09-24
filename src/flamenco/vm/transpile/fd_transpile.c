#include "fd_transpile.h"
#include "../fd_vm_private.h"

void
fd_vm_transpile_bb_splits( ulong *                   bpf_bb_splits,
                           fd_sbpf_program_t const * prog ) {
  ulong text_cnt = prog->info.text_cnt;
  memset( bpf_bb_splits, 0, ( ( text_cnt + 63UL ) >> 6 ) * sizeof(ulong) );

# define FD_VM_SET_BB_SPLIT( pc ) do {                    \
    ulong _pc = (pc);                                     \
    if( _pc < text_cnt )                                  \
      bpf_bb_splits[ _pc >> 6 ] |= ( 1UL<<( _pc&63UL ) ); \
  } while(0)

  FD_VM_SET_BB_SPLIT( 0UL );
  FD_VM_SET_BB_SPLIT( prog->entry_pc );

  ulong const * bpf_text = prog->text;
  int static_syscalls = FD_VM_SBPF_STATIC_SYSCALLS( prog->info.sbpf_version );
  for( ulong pc = 0UL; pc < text_cnt; pc++ ) {
    ulong instr  = bpf_text[ pc ];
    ulong opcode = fd_vm_instr_opcode( instr );
    ulong src    = fd_vm_instr_src   ( instr );
    uint  imm    = fd_vm_instr_imm   ( instr );
    long  offset = (long)fd_vm_instr_offset( instr );

    if( prog->calldests && fd_sbpf_calldests_test( prog->calldests, pc ) ) {
      FD_VM_SET_BB_SPLIT( pc );
    }

    if( opcode == 0x18UL ) { /* LDDW */
      pc++;
      continue;
    }

    ulong cls = opcode & 0x07UL;
    if( cls == 0x05UL || cls == 0x06UL ) {
      if( opcode == 0x85UL /* CALL */ ) {
        if( static_syscalls && src == 1UL ) { /* v3 internal call */
          long target = (long)pc + (long)(int)imm + 1L;
          if( target >= 0 && (ulong)target < text_cnt &&
              fd_vm_instr_opcode( bpf_text[ target ] ) != 0x00UL /* not inside an LDDW */ ) {
            FD_VM_SET_BB_SPLIT( (ulong)target );
          }
        }
      } else if( opcode == 0x95UL /* EXIT */ ) {
        if( pc + 1UL < text_cnt )                     FD_VM_SET_BB_SPLIT( pc + 1UL );
      } else if( opcode != 0x8dUL /* CALLX */ ) {
        long target = (long)pc + 1L + offset;
        if( target >= 0 && (ulong)target < text_cnt ) FD_VM_SET_BB_SPLIT( (ulong)target );
        if( pc + 1UL < text_cnt )                     FD_VM_SET_BB_SPLIT( pc + 1UL );
      }
    }
  }
# undef FD_VM_SET_BB_SPLIT
}
