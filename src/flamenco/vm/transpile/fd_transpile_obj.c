#include "fd_transpile_obj.h"
#include "fd_transpile.h"
#include "../syscall/fd_vm_syscall.h"
#include "../fd_vm_base.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
  char * buf;
  ulong  sz;
  ulong  cap;
} fd_elf_strtab_t;

static int
fd_elf_strtab_init( fd_elf_strtab_t * st,
                    ulong             initial_cap ) {
  st->buf = malloc( initial_cap ? initial_cap : 64UL );
  if( FD_UNLIKELY( !st->buf ) ) return -1;
  st->buf[0] = '\0';
  st->sz     = 1UL;
  st->cap    = initial_cap ? initial_cap : 64UL;
  return 0;
}

static uint
fd_elf_strtab_append( fd_elf_strtab_t * st,
                      char const *      str ) {
  ulong len = strlen( str );
  if( FD_UNLIKELY( st->sz + len + 1UL > st->cap ) ) {
    ulong new_cap = fd_ulong_max( st->cap * 2UL, st->sz + len + 1UL );
    char * new_buf = realloc( st->buf, new_cap );
    if( FD_UNLIKELY( !new_buf ) ) return 0U;
    st->buf = new_buf;
    st->cap = new_cap;
  }
  uint off = (uint)st->sz;
  memcpy( st->buf + off, str, len + 1UL );
  st->sz += len + 1UL;
  return off;
}

static void
fd_elf_strtab_destroy( fd_elf_strtab_t * st ) {
  free( st->buf );
  st->buf = NULL;
  st->sz  = 0UL;
  st->cap = 0UL;
}

/* Syscall function to C symbol name mapping */

static struct {
  fd_sbpf_syscall_func_t func;
  char const *           name;
} const syscall_name_table[] = {
  { fd_vm_syscall_abort,                                 "fd_vm_syscall_abort" },
  { fd_vm_syscall_sol_panic,                             "fd_vm_syscall_sol_panic" },
  { fd_vm_syscall_sol_log,                               "fd_vm_syscall_sol_log" },
  { fd_vm_syscall_sol_log_64,                            "fd_vm_syscall_sol_log_64" },
  { fd_vm_syscall_sol_log_pubkey,                        "fd_vm_syscall_sol_log_pubkey" },
  { fd_vm_syscall_sol_log_compute_units,                 "fd_vm_syscall_sol_log_compute_units" },
  { fd_vm_syscall_sol_log_data,                          "fd_vm_syscall_sol_log_data" },
  { fd_vm_syscall_sol_alloc_free,                        "fd_vm_syscall_sol_alloc_free" },
  { fd_vm_syscall_sol_memcpy,                            "fd_vm_syscall_sol_memcpy" },
  { fd_vm_syscall_sol_memcmp,                            "fd_vm_syscall_sol_memcmp" },
  { fd_vm_syscall_sol_memset,                            "fd_vm_syscall_sol_memset" },
  { fd_vm_syscall_sol_memmove,                           "fd_vm_syscall_sol_memmove" },
  { fd_vm_syscall_sol_get_clock_sysvar,                  "fd_vm_syscall_sol_get_clock_sysvar" },
  { fd_vm_syscall_sol_get_epoch_schedule_sysvar,         "fd_vm_syscall_sol_get_epoch_schedule_sysvar" },
  { fd_vm_syscall_sol_get_rent_sysvar,                   "fd_vm_syscall_sol_get_rent_sysvar" },
  { fd_vm_syscall_sol_get_last_restart_slot_sysvar,      "fd_vm_syscall_sol_get_last_restart_slot_sysvar" },
  { fd_vm_syscall_sol_get_epoch_rewards_sysvar,          "fd_vm_syscall_sol_get_epoch_rewards_sysvar" },
  { fd_vm_syscall_sol_get_sysvar,                        "fd_vm_syscall_sol_get_sysvar" },
  { fd_vm_syscall_sol_get_epoch_stake,                   "fd_vm_syscall_sol_get_epoch_stake" },
  { fd_vm_syscall_sol_get_stack_height,                  "fd_vm_syscall_sol_get_stack_height" },
  { fd_vm_syscall_sol_get_return_data,                   "fd_vm_syscall_sol_get_return_data" },
  { fd_vm_syscall_sol_set_return_data,                   "fd_vm_syscall_sol_set_return_data" },
  { fd_vm_syscall_sol_get_processed_sibling_instruction, "fd_vm_syscall_sol_get_processed_sibling_instruction" },
  { fd_vm_syscall_sol_create_program_address,            "fd_vm_syscall_sol_create_program_address" },
  { fd_vm_syscall_sol_try_find_program_address,          "fd_vm_syscall_sol_try_find_program_address" },
  { fd_vm_syscall_cpi_c,                                 "fd_vm_syscall_cpi_c" },
  { fd_vm_syscall_cpi_rust,                              "fd_vm_syscall_cpi_rust" },
  { fd_vm_syscall_sol_alt_bn128_group_op,                "fd_vm_syscall_sol_alt_bn128_group_op" },
  { fd_vm_syscall_sol_alt_bn128_compression,             "fd_vm_syscall_sol_alt_bn128_compression" },
  { fd_vm_syscall_sol_keccak256,                         "fd_vm_syscall_sol_keccak256" },
  { fd_vm_syscall_sol_sha256,                            "fd_vm_syscall_sol_sha256" },
  { fd_vm_syscall_sol_sha512,                            "fd_vm_syscall_sol_sha512" },
  { fd_vm_syscall_sol_poseidon,                          "fd_vm_syscall_sol_poseidon" },
  { fd_vm_syscall_sol_secp256k1_recover,                 "fd_vm_syscall_sol_secp256k1_recover" },
  { fd_vm_syscall_sol_curve_validate_point,              "fd_vm_syscall_sol_curve_validate_point" },
  { fd_vm_syscall_sol_curve_group_op,                    "fd_vm_syscall_sol_curve_group_op" },
  { fd_vm_syscall_sol_curve_multiscalar_mul,             "fd_vm_syscall_sol_curve_multiscalar_mul" },
  { fd_vm_syscall_sol_curve_decompress,                  "fd_vm_syscall_sol_curve_decompress" },
  { fd_vm_syscall_sol_curve_pairing_map,                 "fd_vm_syscall_sol_curve_pairing_map" },
  { NULL, NULL }
};

static char const *
syscall_c_sym_name( fd_sbpf_syscall_func_t func,
                    char const *           name,
                    char *                 fallback_buf,
                    ulong                  fallback_sz ) {
  for( ulong i=0UL; syscall_name_table[i].func; i++ ) {
    if( syscall_name_table[i].func == func ) {
      return syscall_name_table[i].name;
    }
  }
  if( name ) {
    snprintf( fallback_buf, fallback_sz, "fd_vm_syscall_%s", name );
    return fallback_buf;
  }
  return "fd_vm_syscall_unknown";
}

/* ELF section representation */

typedef struct {
  char const * name;         /* section name */
  uint         name_off;     /* offset in .shstrtab */
  uint         type;         /* SHT_* */
  ulong        flags;        /* SHF_* */
  ulong        align;        /* sh_addralign */
  ulong        entsize;      /* sh_entsize */
  uint         link;         /* sh_link */
  uint         info;         /* sh_info */
  void const * data;         /* section content */
  ulong        sz;           /* section size */
  ulong        offset;       /* file offset */
} fd_elf_sec_t;

uchar *
fd_vm_transpile_obj( uchar *                   elf,
                     ulong *                   elf_sz,
                     fd_sbpf_program_t const * prog,
                     char const *              entrypoint_name_cstr,
                     void *                    scratch,
                     ulong                     scratch_sz ) {

  if( FD_UNLIKELY( !elf || !elf_sz || !prog || !entrypoint_name_cstr || !entrypoint_name_cstr[0] ) ) {
    FD_LOG_WARNING(( "Invalid arguments to fd_vm_transpile_obj" ));
    return NULL;
  }

  ulong text_cnt = prog->info.text_cnt;
  if( FD_UNLIKELY( !text_cnt || prog->entry_pc >= text_cnt ) ) {
    FD_LOG_WARNING(( "Invalid program text_cnt %lu or entry_pc %lu", text_cnt, prog->entry_pc ));
    return NULL;
  }

  /* Syscall table: resolves CALL_IMM targets and names handler symbols */

  fd_sbpf_syscalls_t syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];
  if( FD_UNLIKELY( !fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( syscalls ) ) ) ) {
    FD_LOG_WARNING(( "sbpf_syscalls_new failed" ));
    return NULL;
  }
  fd_vm_syscall_register_all( syscalls, 0 );

  /* Compute basic block split bit vector */

  ulong bb_splits_word_cnt = ( text_cnt + 63UL ) >> 6;
  ulong * bpf_bb_splits = malloc( bb_splits_word_cnt * sizeof(ulong) );
  if( FD_UNLIKELY( !bpf_bb_splits ) ) {
    FD_LOG_WARNING(( "malloc failed for bpf_bb_splits" ));
    return NULL;
  }
  fd_vm_transpile_bb_splits( bpf_bb_splits, prog );

  ulong * bpf_func_starts = malloc( bb_splits_word_cnt * sizeof(ulong) );
  if( FD_UNLIKELY( !bpf_func_starts ) ) {
    FD_LOG_WARNING(( "malloc failed for bpf_func_starts" ));
    free( bpf_bb_splits );
    return NULL;
  }

  fd_vm_transpile_dasm_t d[1];

  ulong reloc_max = FD_VM_TRANSPILE_RELOC_MAX;
  fd_elf64_rela * raw_relocs = malloc( reloc_max * sizeof(fd_elf64_rela) );
  if( FD_UNLIKELY( !raw_relocs ) ) {
    free( bpf_func_starts );
    free( bpf_bb_splits );
    FD_LOG_WARNING(( "malloc failed for raw_relocs" ));
    return NULL;
  }
  ulong reloc_cnt = reloc_max;

  int trans_err = fd_vm_transpile_code( d,
                                        scratch,
                                        scratch_sz,
                                        prog->info.sbpf_version,
                                        (uchar const *)prog->text,
                                        text_cnt,
                                        prog->entry_pc,
                                        (ulong const *)prog->calldests,
                                        syscalls,
                                        bpf_bb_splits,
                                        bpf_func_starts,
                                        raw_relocs,
                                        &reloc_cnt );

  if( FD_UNLIKELY( trans_err ) ) {
    FD_LOG_WARNING(( "fd_vm_transpile_code failed" ));
    free( bpf_func_starts );
    free( bpf_bb_splits );
    free( raw_relocs );
    return NULL;
  }

  /* Link DynASM code section */

  size_t code_sz = 0;
  int link_res = dasm_link( d, &code_sz );
  if( FD_UNLIKELY( link_res != 0 ) ) {
    FD_LOG_WARNING(( "dasm_link failed: %d", link_res ));
    free( raw_relocs );
    return NULL;
  }

  void * text_buf = malloc( code_sz ? code_sz : 1UL );
  if( FD_UNLIKELY( !text_buf ) ) {
    FD_LOG_WARNING(( "malloc failed for text_buf" ));
    free( raw_relocs );
    return NULL;
  }

  int enc_res = dasm_encode( d, text_buf );
  if( FD_UNLIKELY( enc_res != 0 ) ) {
    FD_LOG_WARNING(( "dasm_encode failed: %d", enc_res ));
    free( text_buf );
    free( raw_relocs );
    return NULL;
  }

  /* Resolve relocation offsets from DynASM PC labels */

  ulong dasm_lbl_reloc0 = FD_VM_TRANSPILE_DASM_LBL_RELOC0( text_cnt );
  for( ulong i = 0UL; i < reloc_cnt; i++ ) {
    int ofs = dasm_getpclabel( d, (uint)(dasm_lbl_reloc0 + i) );
    if( FD_UNLIKELY( ofs < 0 ) ) {
      FD_LOG_WARNING(( "failed to resolve relocation %lu PC label: %d", i, ofs ));
      free( text_buf );
      free( raw_relocs );
      return NULL;
    }
    raw_relocs[ i ].r_offset = (ulong)ofs;
  }

  /* Build callx tables (see emit_callx_handler):
     bitmap: bit per pc, set if pc starts a basic block
     seq:    running popcount of bitmap words
     jmp:    per basic block, x86 code offset relative to the jmp table
             (materialized via .rela.rodata against .text) */

  ulong bb_cnt = 0UL;
  for( ulong w = 0UL; w < bb_splits_word_cnt; w++ ) bb_cnt += (ulong)fd_ulong_popcnt( bpf_bb_splits[ w ] );

  ulong const rodata_bitmap_off = 0UL;
  ulong const rodata_seq_off    = rodata_bitmap_off + bb_splits_word_cnt * sizeof(ulong);
  ulong const rodata_jmp_off    = rodata_seq_off    + bb_splits_word_cnt * sizeof(ulong);
  ulong const rodata_sz         = rodata_jmp_off    + bb_cnt * sizeof(int);

  uchar *         rodata       = malloc( rodata_sz );
  fd_elf64_rela * rodata_relocs = malloc( fd_ulong_max( bb_cnt, 1UL ) * sizeof(fd_elf64_rela) );
  if( FD_UNLIKELY( !rodata || !rodata_relocs ) ) {
    FD_LOG_WARNING(( "malloc failed for rodata" ));
    free( rodata_relocs );
    free( rodata );
    free( bpf_bb_splits );
    free( text_buf );
    free( raw_relocs );
    return NULL;
  }

  memcpy( rodata + rodata_bitmap_off, bpf_bb_splits, bb_splits_word_cnt * sizeof(ulong) );
  ulong * seq = (ulong *)( rodata + rodata_seq_off );
  int *   jmp = (int *)  ( rodata + rodata_jmp_off );
  ulong bb_idx = 0UL;
  for( ulong w = 0UL; w < bb_splits_word_cnt; w++ ) {
    seq[ w ] = bb_idx;
    ulong word = bpf_bb_splits[ w ];
    while( word ) {
      int   bit = fd_ulong_find_lsb( word );
      word &= word - 1UL;
      ulong pc  = ( w << 6 ) + (ulong)bit;
      int   ofs = dasm_getpclabel( d, (uint)pc );
      if( FD_UNLIKELY( ofs < 0 ) ) {
        FD_LOG_WARNING(( "failed to resolve basic block %lu PC label: %d", pc, ofs ));
        free( rodata_relocs );
        free( rodata );
        free( bpf_bb_splits );
        free( text_buf );
        free( raw_relocs );
        return NULL;
      }
      jmp[ bb_idx ] = 0;
      /* S + A - P = .text + ofs + 4*bb_idx - (.rodata + jmp_off + 4*bb_idx) */
      rodata_relocs[ bb_idx ] = (fd_elf64_rela){
        .r_offset = rodata_jmp_off + bb_idx * sizeof(int),
        .r_info   = FD_ELF64_R_INFO( 1U /* .text section symbol */, FD_ELF_R_X86_64_PC32 ),
        .r_addend = (long)ofs + (long)( bb_idx * sizeof(int) )
      };
      bb_idx++;
    }
  }
  free( bpf_bb_splits );
  bpf_bb_splits = NULL;

  /* Resolve sBPF function boundaries: one symbol per function, plus
     one for the runtime helper subroutines following the instruction
     stream.  Functions are laid out in pc order, so the function
     starting at the next set bit ends the previous one. */

  ulong func_cnt = 0UL;
  for( ulong w = 0UL; w < bb_splits_word_cnt; w++ ) func_cnt += (ulong)fd_ulong_popcnt( bpf_func_starts[ w ] );
  struct { ulong pc; ulong off; } * funcs = malloc( fd_ulong_max( func_cnt, 1UL ) * sizeof(*funcs) );
  if( FD_UNLIKELY( !funcs ) ) {
    FD_LOG_WARNING(( "malloc failed for funcs" ));
    free( bpf_func_starts );
    free( rodata_relocs );
    free( rodata );
    free( text_buf );
    free( raw_relocs );
    return NULL;
  }
  ulong func_idx = 0UL;
  for( ulong w = 0UL; w < bb_splits_word_cnt; w++ ) {
    ulong word = bpf_func_starts[ w ];
    while( word ) {
      ulong pc = ( w << 6 ) + (ulong)fd_ulong_find_lsb( word );
      word &= word - 1UL;
      int ofs = dasm_getpclabel( d, (uint)pc );
      if( FD_UNLIKELY( ofs < 0 ) ) {
        FD_LOG_WARNING(( "failed to resolve function %lu PC label: %d", pc, ofs ));
        free( funcs );
        free( bpf_func_starts );
        free( rodata_relocs );
        free( rodata );
        free( text_buf );
        free( raw_relocs );
        return NULL;
      }
      funcs[ func_idx ].pc  = pc;
      funcs[ func_idx ].off = (ulong)ofs;
      func_idx++;
    }
  }
  free( bpf_func_starts );
  bpf_func_starts = NULL;
  int text_end_ofs = dasm_getpclabel( d, (uint)( FD_VM_TRANSPILE_DASM_LBL_RELOC0( text_cnt )-1UL ) );
  if( FD_UNLIKELY( text_end_ofs < 0 || (ulong)text_end_ofs > (ulong)code_sz ) ) {
    FD_LOG_WARNING(( "failed to resolve text end PC label: %d", text_end_ofs ));
    free( funcs );
    free( rodata_relocs );
    free( rodata );
    free( text_buf );
    free( raw_relocs );
    return NULL;
  }
  ulong const text_end_off = (ulong)text_end_ofs;

  /* Build .strtab and .symtab */

  fd_elf_strtab_t strtab;
  if( FD_UNLIKELY( fd_elf_strtab_init( &strtab, 256UL ) ) ) {
    FD_LOG_WARNING(( "failed to init strtab" ));
    free( funcs );
    free( rodata_relocs );
    free( rodata );
    free( text_buf );
    free( raw_relocs );
    return NULL;
  }

  ulong sym_cap = 16UL + func_cnt + reloc_cnt;
  fd_elf64_sym * syms = malloc( sym_cap * sizeof(fd_elf64_sym) );
  if( FD_UNLIKELY( !syms ) ) {
    FD_LOG_WARNING(( "malloc failed for syms" ));
    free( funcs );
    fd_elf_strtab_destroy( &strtab );
    free( rodata_relocs );
    free( rodata );
    free( text_buf );
    free( raw_relocs );
    return NULL;
  }
  memset( syms, 0, sym_cap * sizeof(fd_elf64_sym) );

  /* Section indices in final ELF */

  ushort const sec_idx_text     = 1; /* 2: .rela.text */
  ushort const sec_idx_rodata   = 3; /* 4: .rela.rodata, 5: .comment, 6: .note.GNU-stack */
  ushort const sec_idx_symtab   = 7;
  ushort const sec_idx_strtab   = 8;
  ushort const sec_idx_shstrtab = 9;

  /* Symbol 0: STN_UNDEF */
  ulong sym_cnt = 0UL;
  syms[ sym_cnt++ ] = (fd_elf64_sym){ 0 };

  /* Local section symbols */
  /* Symbol 1: .text */
  syms[ sym_cnt++ ] = (fd_elf64_sym){
    .st_name  = 0U,
    .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_LOCAL, FD_ELF_STT_SECTION ),
    .st_shndx = sec_idx_text,
  };
  /* Symbol 2: .rodata */
  syms[ sym_cnt++ ] = (fd_elf64_sym){
    .st_name  = 0U,
    .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_LOCAL, FD_ELF_STT_SECTION ),
    .st_shndx = sec_idx_rodata,
  };

  /* Local object symbols for the callx tables */
  uint raw_sym_to_symtab[ 256 ] = {0};
  struct { uint raw_sym; char const * name; ulong off; ulong sz; } const rodata_syms[3] = {
    { FD_VM_TRANSPILE_SYM_BB_BITMAP, "fd_vm_transpiled_bb_bitmap", rodata_bitmap_off, rodata_seq_off - rodata_bitmap_off },
    { FD_VM_TRANSPILE_SYM_BB_SEQ,    "fd_vm_transpiled_bb_seq",    rodata_seq_off,    rodata_jmp_off - rodata_seq_off    },
    { FD_VM_TRANSPILE_SYM_BB_JMP,    "fd_vm_transpiled_bb_jmp",    rodata_jmp_off,    rodata_sz      - rodata_jmp_off    },
  };
  for( ulong i = 0UL; i < 3UL; i++ ) {
    raw_sym_to_symtab[ rodata_syms[ i ].raw_sym ] = (uint)sym_cnt;
    syms[ sym_cnt++ ] = (fd_elf64_sym){
      .st_name  = fd_elf_strtab_append( &strtab, rodata_syms[ i ].name ),
      .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_LOCAL, FD_ELF_STT_OBJECT ),
      .st_shndx = sec_idx_rodata,
      .st_value = rodata_syms[ i ].off,
      .st_size  = rodata_syms[ i ].sz
    };
  }

  /* Local symbols: sBPF functions (named by pc) and runtime helpers */
  for( ulong i = 0UL; i < func_cnt; i++ ) {
    char name[ 32 ];
    fd_cstr_printf( name, sizeof(name), NULL, "sbpf_%lu", funcs[ i ].pc );
    ulong end = ( i+1UL < func_cnt ) ? funcs[ i+1UL ].off : text_end_off;
    syms[ sym_cnt++ ] = (fd_elf64_sym){
      .st_name  = fd_elf_strtab_append( &strtab, name ),
      .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_LOCAL, FD_ELF_STT_FUNC ),
      .st_shndx = sec_idx_text,
      .st_value = funcs[ i ].off,
      .st_size  = end - funcs[ i ].off
    };
  }
  syms[ sym_cnt++ ] = (fd_elf64_sym){
    .st_name  = fd_elf_strtab_append( &strtab, "fd_vm_transpiled_helpers" ),
    .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_LOCAL, FD_ELF_STT_FUNC ),
    .st_shndx = sec_idx_text,
    .st_value = text_end_off,
    .st_size  = (ulong)code_sz - text_end_off
  };
  ulong const root_sz = func_cnt ? funcs[ 0 ].off : text_end_off;
  free( funcs );
  funcs = NULL;

  uint const first_global_sym_idx = (uint)sym_cnt;

  /* Global symbol: Entrypoint function (the root frame prologue) */
  uint ep_name_off = fd_elf_strtab_append( &strtab, entrypoint_name_cstr );
  syms[ sym_cnt++ ] = (fd_elf64_sym){
    .st_name  = ep_name_off,
    .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_GLOBAL, FD_ELF_STT_FUNC ),
    .st_shndx = sec_idx_text,
    .st_value = 0UL,
    .st_size  = root_sz
  };

  /* Undefined external symbols for relocations:
     Map raw symbol ID => symbol table index */

  char fallback_buf[ 128 ];

  for( ulong i = 0UL; i < reloc_cnt; i++ ) {
    uint raw_sym = FD_ELF64_R_SYM( raw_relocs[i].r_info );
    uint sym_idx = 0U;

    if( raw_sym < 256U && raw_sym_to_symtab[ raw_sym ] ) {
      sym_idx = raw_sym_to_symtab[ raw_sym ];
    } else {
      char const * sym_name = NULL;
      if( raw_sym == FD_VM_TRANSPILE_SYM_MMU_TRANSLATE ) {
        sym_name = "fd_vm_transpiled_mmu_translate";
      } else if( raw_sym == FD_VM_TRANSPILE_SYM_FRAME_INIT ) {
        sym_name = "fd_vm_transpiled_frame_init";
      } else if( raw_sym >= FD_VM_TRANSPILE_SYM_MAX &&
                 raw_sym < FD_VM_TRANSPILE_SYM_MAX + FD_SBPF_SYSCALLS_SLOT_CNT ) {
        ulong slot = (ulong)( raw_sym - FD_VM_TRANSPILE_SYM_MAX );
        fd_sbpf_syscalls_t const * sys = &syscalls[ slot ];
        sym_name = syscall_c_sym_name( sys->func, sys->name, fallback_buf, sizeof(fallback_buf) );
      } else {
        sym_name = "unknown_symbol";
      }

      uint name_off = fd_elf_strtab_append( &strtab, sym_name );
      sym_idx = (uint)sym_cnt++;
      syms[ sym_idx ] = (fd_elf64_sym){
        .st_name  = name_off,
        .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_GLOBAL, FD_ELF_STT_FUNC ),
        .st_shndx = FD_ELF_SHN_UNDEF,
        .st_value = 0UL,
        .st_size  = 0UL
      };
      if( raw_sym < 256U ) {
        raw_sym_to_symtab[ raw_sym ] = sym_idx;
      }
    }

    raw_relocs[ i ].r_info = FD_ELF64_R_INFO( sym_idx, FD_ELF64_R_TYPE( raw_relocs[i].r_info ) );
  }

  /* Construct .comment string */

  static char const comment_data[] = "Firedancer sBPF transpiler";
  ulong const comment_sz = sizeof(comment_data);

  /* Build .shstrtab */

  fd_elf_strtab_t shstrtab;
  if( FD_UNLIKELY( fd_elf_strtab_init( &shstrtab, 128UL ) ) ) {
    FD_LOG_WARNING(( "failed to init shstrtab" ));
    free( syms );
    fd_elf_strtab_destroy( &strtab );
    free( rodata_relocs );
    free( rodata );
    free( text_buf );
    free( raw_relocs );
    return NULL;
  }

  /* Define sections table.
     Future possibility: DWARFv5 source code embedding sections
     (.debug_info, .debug_abbrev, .debug_line, etc.) can be appended here. */

  fd_elf_sec_t sec[ 16 ];
  ulong sec_cnt = 0UL;

  /* Section 0: NULL section */
  sec[ sec_cnt++ ] = (fd_elf_sec_t){
    .name = "",
    .type = FD_ELF_SHT_NULL
  };

  /* Section 1: .text */
  sec[ sec_cnt++ ] = (fd_elf_sec_t){
    .name    = ".text",
    .type    = FD_ELF_SHT_PROGBITS,
    .flags   = FD_ELF_SHF_ALLOC | FD_ELF_SHF_EXECINSTR,
    .align   = 16UL,
    .data    = text_buf,
    .sz      = (ulong)code_sz
  };

  /* Section 2: .rela.text */
  sec[ sec_cnt++ ] = (fd_elf_sec_t){
    .name    = ".rela.text",
    .type    = FD_ELF_SHT_RELA,
    .flags   = FD_ELF_SHF_INFO_LINK,
    .align   = 8UL,
    .entsize = sizeof(fd_elf64_rela),
    .link    = sec_idx_symtab,
    .info    = sec_idx_text,
    .data    = reloc_cnt ? (void const *)raw_relocs : NULL,
    .sz      = reloc_cnt * sizeof(fd_elf64_rela)
  };

  /* Section 3: .rodata (callx tables) */
  sec[ sec_cnt++ ] = (fd_elf_sec_t){
    .name    = ".rodata",
    .type    = FD_ELF_SHT_PROGBITS,
    .flags   = FD_ELF_SHF_ALLOC,
    .align   = 8UL,
    .data    = rodata,
    .sz      = rodata_sz
  };

  /* Section 4: .rela.rodata */
  sec[ sec_cnt++ ] = (fd_elf_sec_t){
    .name    = ".rela.rodata",
    .type    = FD_ELF_SHT_RELA,
    .flags   = FD_ELF_SHF_INFO_LINK,
    .align   = 8UL,
    .entsize = sizeof(fd_elf64_rela),
    .link    = sec_idx_symtab,
    .info    = sec_idx_rodata,
    .data    = bb_cnt ? (void const *)rodata_relocs : NULL,
    .sz      = bb_cnt * sizeof(fd_elf64_rela)
  };

  /* Section 5: .comment */
  sec[ sec_cnt++ ] = (fd_elf_sec_t){
    .name    = ".comment",
    .type    = FD_ELF_SHT_PROGBITS,
    .flags   = 0UL,
    .align   = 1UL,
    .entsize = 1UL,
    .data    = comment_data,
    .sz      = comment_sz
  };

  /* Section 6: .note.GNU-stack (noexecstack) */
  sec[ sec_cnt++ ] = (fd_elf_sec_t){
    .name    = ".note.GNU-stack",
    .type    = FD_ELF_SHT_PROGBITS,
    .flags   = 0UL,
    .align   = 1UL,
    .data    = NULL,
    .sz      = 0UL
  };

  /* Section 7: .symtab */
  sec[ sec_cnt++ ] = (fd_elf_sec_t){
    .name    = ".symtab",
    .type    = FD_ELF_SHT_SYMTAB,
    .flags   = 0UL,
    .align   = 8UL,
    .entsize = sizeof(fd_elf64_sym),
    .link    = sec_idx_strtab,
    .info    = first_global_sym_idx,
    .data    = syms,
    .sz      = sym_cnt * sizeof(fd_elf64_sym)
  };

  /* Section 8: .strtab */
  sec[ sec_cnt++ ] = (fd_elf_sec_t){
    .name    = ".strtab",
    .type    = FD_ELF_SHT_STRTAB,
    .flags   = 0UL,
    .align   = 1UL,
    .data    = strtab.buf,
    .sz      = strtab.sz
  };

  /* Section 9: .shstrtab */
  uint const shstrtab_idx = (uint)sec_cnt;
  FD_TEST( shstrtab_idx==sec_idx_shstrtab );
  sec[ sec_cnt++ ] = (fd_elf_sec_t){
    .name    = ".shstrtab",
    .type    = FD_ELF_SHT_STRTAB,
    .flags   = 0UL,
    .align   = 1UL,
    .data    = NULL, /* set below after population */
    .sz      = 0UL
  };

  /* Populate section name offsets in .shstrtab */

  for( ulong i = 0UL; i < sec_cnt; i++ ) {
    sec[ i ].name_off = fd_elf_strtab_append( &shstrtab, sec[ i ].name );
  }
  sec[ shstrtab_idx ].data = shstrtab.buf;
  sec[ shstrtab_idx ].sz   = shstrtab.sz;

  /* Compute file layout offsets */

  ulong cur_off = sizeof(fd_elf64_ehdr);
  for( ulong i = 1UL; i < sec_cnt; i++ ) {
    ulong align = sec[ i ].align ? sec[ i ].align : 1UL;
    if( sec[ i ].sz > 0UL && sec[ i ].data ) {
      cur_off = fd_ulong_align_up( cur_off, align );
      sec[ i ].offset = cur_off;
      cur_off += sec[ i ].sz;
    } else {
      sec[ i ].offset = cur_off;
    }
  }

  ulong shoff    = fd_ulong_align_up( cur_off, 8UL );
  ulong total_sz = shoff + sec_cnt * sizeof(fd_elf64_shdr);

  if( FD_UNLIKELY( total_sz > *elf_sz ) ) {
    FD_LOG_WARNING(( "ELF buffer too small: capacity %lu, required %lu", *elf_sz, total_sz ));
    fd_elf_strtab_destroy( &shstrtab );
    free( syms );
    fd_elf_strtab_destroy( &strtab );
    free( rodata_relocs );
    free( rodata );
    free( text_buf );
    free( raw_relocs );
    return NULL;
  }

  /* Zero output buffer and write ELF Header */

  memset( elf, 0, total_sz );

  fd_elf64_ehdr * ehdr = (fd_elf64_ehdr *)elf;
  ehdr->e_ident[ FD_ELF_EI_MAG0 ]       = 0x7f;
  ehdr->e_ident[ FD_ELF_EI_MAG1 ]       = 'E';
  ehdr->e_ident[ FD_ELF_EI_MAG2 ]       = 'L';
  ehdr->e_ident[ FD_ELF_EI_MAG3 ]       = 'F';
  ehdr->e_ident[ FD_ELF_EI_CLASS ]      = FD_ELF_CLASS_64;
  ehdr->e_ident[ FD_ELF_EI_DATA ]       = FD_ELF_DATA_LE;
  ehdr->e_ident[ FD_ELF_EI_VERSION ]    = 1;
  ehdr->e_ident[ FD_ELF_EI_OSABI ]      = FD_ELF_OSABI_NONE;
  ehdr->e_ident[ FD_ELF_EI_ABIVERSION ] = 0;
  ehdr->e_type      = FD_ELF_ET_REL;
  ehdr->e_machine   = FD_ELF_EM_X86_64;
  ehdr->e_version   = 1;
  ehdr->e_entry     = 0UL;
  ehdr->e_phoff     = 0UL;
  ehdr->e_shoff     = shoff;
  ehdr->e_flags     = 0;
  ehdr->e_ehsize    = sizeof(fd_elf64_ehdr);
  ehdr->e_phentsize = 0;
  ehdr->e_phnum     = 0;
  ehdr->e_shentsize = sizeof(fd_elf64_shdr);
  ehdr->e_shnum     = (ushort)sec_cnt;
  ehdr->e_shstrndx  = (ushort)shstrtab_idx;

  /* Write section data */

  for( ulong i = 1UL; i < sec_cnt; i++ ) {
    if( sec[ i ].sz > 0UL && sec[ i ].data ) {
      memcpy( elf + sec[ i ].offset, sec[ i ].data, sec[ i ].sz );
    }
  }

  /* Write section header table */

  fd_elf64_shdr * shdrs = (fd_elf64_shdr *)( elf + shoff );
  for( ulong i = 0UL; i < sec_cnt; i++ ) {
    shdrs[ i ] = (fd_elf64_shdr){
      .sh_name      = sec[ i ].name_off,
      .sh_type      = sec[ i ].type,
      .sh_flags     = sec[ i ].flags,
      .sh_addr      = 0UL,
      .sh_offset    = sec[ i ].offset,
      .sh_size      = sec[ i ].sz,
      .sh_link      = sec[ i ].link,
      .sh_info      = sec[ i ].info,
      .sh_addralign = sec[ i ].align,
      .sh_entsize   = sec[ i ].entsize
    };
  }

  /* Cleanup temporary buffers */

  fd_elf_strtab_destroy( &shstrtab );
  free( syms );
  fd_elf_strtab_destroy( &strtab );
  free( rodata_relocs );
  free( rodata );
  free( text_buf );
  free( raw_relocs );

  *elf_sz = total_sz;
  return elf;
}
