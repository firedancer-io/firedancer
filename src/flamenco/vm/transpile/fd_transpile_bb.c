#include "fd_transpile_bb.h"
#include "../fd_vm_private.h"

ulong
fd_transpile_bb_splits( ulong *       bb_splits,
                        ulong         sbpf_version,
                        ulong const * bpf_text,
                        ulong         bpf_text_cnt,
                        ulong         bpf_entry_pc,
                        ulong const * bpf_calldests,
                        uchar const * bpf_rodata,
                        ulong         bpf_rodata_sz,
                        ulong         bpf_text_off ) {
  ulong word_cnt = (bpf_text_cnt+63UL)>>6;
  memset( bb_splits, 0, word_cnt*sizeof(ulong) );

# define SET_BB_SPLIT( pc ) do {                    \
    ulong _pc = (pc);                               \
    if( _pc<bpf_text_cnt )                          \
      bb_splits[ _pc>>6 ] |= ( 1UL<<( _pc&63UL ) ); \
  } while(0)

  SET_BB_SPLIT( 0UL );
  SET_BB_SPLIT( bpf_entry_pc );

  /* Address-taken functions (vtables, closures) reach callx through
     pointers the loader relocated into the read-only segment.  Any
     64-bit word in the loaded image pointing at an instruction slot is
     treated as a possible call target.  Pointers in .data.rel.ro are
     only 4-byte aligned, and false positives merely split a block. */
  ulong text_lo = FD_VM_MEM_MAP_PROGRAM_REGION_START + bpf_text_off;
  ulong text_hi = text_lo + 8UL*bpf_text_cnt;
  for( ulong off=0UL; off+8UL<=bpf_rodata_sz; off+=4UL ) {
    ulong v = FD_LOAD( ulong, bpf_rodata+off );
    if( v>=text_lo && v<text_hi && !((v-text_lo)&7UL) ) SET_BB_SPLIT( (v-text_lo)>>3 );
  }

  int static_syscalls = FD_VM_SBPF_STATIC_SYSCALLS( sbpf_version );
  for( ulong pc=0UL; pc<bpf_text_cnt; pc++ ) {
    ulong instr  = bpf_text[ pc ];
    ulong opcode = fd_vm_instr_opcode( instr );
    ulong src    = fd_vm_instr_src   ( instr );
    uint  imm    = fd_vm_instr_imm   ( instr );
    long  offset = (long)fd_vm_instr_offset( instr );

    if( bpf_calldests && fd_sbpf_calldests_test( bpf_calldests, pc ) ) {
      SET_BB_SPLIT( pc );
    }

    if( opcode==0x18UL ) { /* LDDW */
      if( pc+1UL<bpf_text_cnt ) {
        ulong v = (ulong)imm | ( bpf_text[ pc+1UL ] & 0xffffffff00000000UL );
        if( v>=text_lo && v<text_hi && !((v-text_lo)&7UL) ) SET_BB_SPLIT( (v-text_lo)>>3 );
      }
      pc++;
      continue;
    }

    ulong cls = opcode & 0x07UL;
    if( cls==0x05UL || cls==0x06UL ) {
      if( opcode==0x85UL /* CALL */ ) {
        if( static_syscalls && src==1UL ) { /* v3 internal call */
          long target = (long)pc + (long)(int)imm + 1L;
          if( target>=0 && (ulong)target<bpf_text_cnt &&
              fd_vm_instr_opcode( bpf_text[ target ] )!=0x00UL /* not inside an LDDW */ ) {
            SET_BB_SPLIT( (ulong)target );
          }
        }
      } else if( opcode==0x95UL /* EXIT */ ) {
        if( pc+1UL<bpf_text_cnt )                    SET_BB_SPLIT( pc+1UL );
      } else if( opcode!=0x8dUL /* CALLX */ ) {
        long target = (long)pc + 1L + offset;
        if( target>=0 && (ulong)target<bpf_text_cnt ) SET_BB_SPLIT( (ulong)target );
        if( pc+1UL<bpf_text_cnt )                    SET_BB_SPLIT( pc+1UL );
      }
    }
  }
# undef SET_BB_SPLIT

  for( ulong pc=0UL; pc+1UL<bpf_text_cnt; pc++ ) {
    if( fd_vm_instr_opcode( bpf_text[ pc ] )==0x18UL ) {
      bb_splits[ (pc+1UL)>>6 ] &= ~( 1UL<<( (pc+1UL)&63UL ) );
      pc++;
    }
  }

  ulong cnt = 0UL;
  for( ulong w=0UL; w<word_cnt; w++ ) cnt += (ulong)fd_ulong_popcnt( bb_splits[ w ] );
  return cnt;
}
