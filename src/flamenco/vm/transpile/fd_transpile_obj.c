#include "fd_transpile_obj.h"
#include "fd_transpile.h"
#include "../syscall/fd_vm_syscall.h"
#include "../fd_vm_base.h"
#include "../../../util/cstr/fd_cstr.h"
#include "../../../util/io/fd_io.h"
#include "../../../ballet/base58/fd_base58.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* fd_elf_strtab_t is a fixed capacity ELF string table.  Appends that
   do not fit set err and return offset 0. */

typedef struct {
  char * buf;
  ulong  sz;
  ulong  cap;
  int    err;
} fd_elf_strtab_t;

static void
fd_elf_strtab_init( fd_elf_strtab_t * st,
                    char *            buf,
                    ulong             cap ) { /* cap>=1 */
  buf[0]  = '\0';
  st->buf = buf;
  st->sz  = 1UL;
  st->cap = cap;
  st->err = 0;
}

static uint
fd_elf_strtab_append( fd_elf_strtab_t * st,
                      char const *      str ) {
  ulong len = strlen( str );
  if( FD_UNLIKELY( len+1UL > st->cap - st->sz ) ) {
    st->err = 1;
    return 0U;
  }
  uint off = (uint)st->sz;
  memcpy( st->buf + off, str, len + 1UL );
  st->sz += len + 1UL;
  return off;
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
syscall_c_sym_name( fd_sbpf_syscall_func_t func ) {
  for( ulong i=0UL; syscall_name_table[i].func; i++ ) {
    if( syscall_name_table[i].func == func ) {
      return syscall_name_table[i].name;
    }
  }
  return NULL;
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

/* elf_write serializes a relocatable x86_64 ELF object with the given
   sections to elf (capacity *elf_sz).  The last section must be
   .shstrtab with NULL data (populated here).  Returns elf on success
   (sets *elf_sz), or NULL on failure (logs warning). */

static uchar *
elf_write( uchar *        elf,
           ulong *        elf_sz,
           fd_elf_sec_t * sec,
           ulong          sec_cnt ) {

  char            shstrtab_buf[ 256 ];
  fd_elf_strtab_t shstrtab;
  fd_elf_strtab_init( &shstrtab, shstrtab_buf, sizeof(shstrtab_buf) );
  uint const shstrtab_idx = (uint)( sec_cnt-1UL );

  /* Populate section name offsets in .shstrtab */

  for( ulong i = 0UL; i < sec_cnt; i++ ) {
    sec[ i ].name_off = fd_elf_strtab_append( &shstrtab, sec[ i ].name );
  }
  sec[ shstrtab_idx ].data = shstrtab.buf;
  sec[ shstrtab_idx ].sz   = shstrtab.sz;
  if( FD_UNLIKELY( shstrtab.err ) ) {
    FD_LOG_WARNING(( "ELF string table overflow" ));
    return NULL;
  }

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

  *elf_sz = total_sz;
  return elf;
}

ulong
fd_transpiler_export_obj( fd_transpiler_t *          t,
                          fd_sbpf_syscalls_t const * syscalls,
                          uchar *                    elf,
                          ulong                      elf_max ) {

  if( FD_UNLIKELY( !t || !elf || !elf_max ) ) {
    FD_LOG_WARNING(( "Invalid arguments to fd_transpiler_export_obj" ));
    return 0UL;
  }
  if( FD_UNLIKELY( !t->code_sz ) ) {
    FD_LOG_WARNING(( "transpiler state has no code" ));
    return 0UL;
  }

  /* Resolve relocations */

  ulong reloc_cnt = t->reloc_cnt;
  fd_elf64_rela * text_relas = malloc( fd_ulong_max( reloc_cnt, 1UL ) * sizeof(fd_elf64_rela) );
  if( FD_UNLIKELY( !text_relas ) ) {
    FD_LOG_WARNING(( "malloc failed for text_relas" ));
    return 0UL;
  }

  for( ulong i = 0UL; i < reloc_cnt; i++ ) {
    ulong r_offset = t->reloc[ i ].r_offset;
    if( FD_UNLIKELY( r_offset + 4UL > t->code_sz ) ) {
      FD_LOG_WARNING(( "relocation %lu offset %lu out of bounds (code_sz %lu)", i, r_offset, t->code_sz ));
      free( text_relas );
      return 0UL;
    }
    text_relas[ i ].r_offset = r_offset;
    text_relas[ i ].r_addend = t->reloc[ i ].r_addend;
  }

  /* Build symbol names */

  FD_BASE58_ENCODE_32_BYTES( t->meta.prog_id, prog_id_b58 );
  char export_sym_name[ 128 ];
  if( FD_UNLIKELY( !fd_cstr_printf_check( export_sym_name, sizeof(export_sym_name), NULL,
                   "fd_transpiled_ext_%s", prog_id_b58 ) ) ) {
    FD_LOG_WARNING(( "symbol name overflow" ));
    free( text_relas );
    return 0UL;
  }

  ulong strtab_cap = 512UL + strlen( export_sym_name ) + reloc_cnt * 64UL + t->sym_cnt * 48UL;
  char * strtab_buf = malloc( strtab_cap );
  ulong sym_cap = 16UL + reloc_cnt + t->sym_cnt;
  fd_elf64_sym * syms = malloc( sym_cap * sizeof(fd_elf64_sym) );
  if( FD_UNLIKELY( !strtab_buf || !syms ) ) {
    FD_LOG_WARNING(( "malloc failed" ));
    free( strtab_buf );
    free( syms );
    free( text_relas );
    return 0UL;
  }
  memset( syms, 0, sym_cap * sizeof(fd_elf64_sym) );

  fd_elf_strtab_t strtab;
  fd_elf_strtab_init( &strtab, strtab_buf, strtab_cap );

  ushort const sec_idx_text   = 1;
  ushort const sec_idx_rodata = 3;
  ushort const sec_idx_symtab = 7;
  ushort const sec_idx_strtab = 8;

  /* Symbol 0: STN_UNDEF */
  ulong sym_cnt = 0UL;
  syms[ sym_cnt++ ] = (fd_elf64_sym){ 0 };

  /* Local section symbols:
     Symbol 1: .text
     Symbol 2: .data.rel.ro */
  syms[ sym_cnt++ ] = (fd_elf64_sym){
    .st_name  = 0U,
    .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_LOCAL, FD_ELF_STT_SECTION ),
    .st_shndx = sec_idx_text
  };
  syms[ sym_cnt++ ] = (fd_elf64_sym){
    .st_name  = 0U,
    .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_LOCAL, FD_ELF_STT_SECTION ),
    .st_shndx = sec_idx_rodata
  };

  /* .data.rel.ro layout: export struct, then transpiler tables.
     export.exec is an absolute pointer patched by a dynamic relocation
     in PIC links, so the section must be writable (RELRO). */
  ulong const tables_off = fd_ulong_align_up( sizeof(fd_transpile_export_t), 8UL );
  ulong const rodata_sz  = tables_off + t->rodata_sz;

  /* Local named ranges, for disassemblers and debuggers.  The exec
     prologue at offset 0 runs up to the first named range. */
  ulong const exec_sz = t->sym_cnt ? (ulong)t->sym[ 0 ].off : t->code_sz;
  syms[ sym_cnt++ ] = (fd_elf64_sym){
    .st_name  = fd_elf_strtab_append( &strtab, "fd_xlat_exec" ),
    .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_LOCAL, FD_ELF_STT_FUNC ),
    .st_shndx = sec_idx_text,
    .st_value = 0UL,
    .st_size  = exec_sz
  };
  syms[ sym_cnt++ ] = (fd_elf64_sym){
    .st_name  = fd_elf_strtab_append( &strtab, "fd_xlat_bb_tables" ),
    .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_LOCAL, FD_ELF_STT_OBJECT ),
    .st_shndx = sec_idx_rodata,
    .st_value = tables_off,
    .st_size  = t->rodata_sz
  };
  for( ulong i=0UL; i<t->sym_cnt; i++ ) {
    fd_transpiler_sym_t const * s = &t->sym[ i ];
    char name[ 96 ] = {0};
    switch( s->kind ) {
    case FD_TRANSPILER_SYM_KIND_FUNC:
      if( s->arg==t->meta.entry_pc ) fd_cstr_printf( name, sizeof(name), NULL, "sbpf_entrypoint" );
      break;
    case FD_TRANSPILER_SYM_KIND_THUNK:
      break;
    case FD_TRANSPILER_SYM_KIND_SYSCALL: {
      char const * sname = ( syscalls && s->arg<FD_SBPF_SYSCALLS_SLOT_CNT ) ? syscalls[ s->arg ].name : NULL;
      if( sname ) fd_cstr_printf( name, sizeof(name), NULL, "sbpf_syscall_%s", sname );
      else        fd_cstr_printf( name, sizeof(name), NULL, "sbpf_syscall_slot%u", s->arg );
      break;
    }
    case FD_TRANSPILER_SYM_KIND_HELPER: {
      char const * hname = fd_transpiler_helper_name( s->arg );
      fd_cstr_printf( name, sizeof(name), NULL, "fd_xlat_%s", hname ? hname : "helper" );
      break;
    }
    default:
      continue;
    }
    syms[ sym_cnt++ ] = (fd_elf64_sym){
      .st_name  = name[0] ? fd_elf_strtab_append( &strtab, name ) : 0U,
      .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_LOCAL, FD_ELF_STT_FUNC ),
      .st_shndx = sec_idx_text,
      .st_value = s->off,
      .st_size  = s->sz
    };
  }

  /* First non-local symbol index */
  uint const first_global = (uint)sym_cnt;

  /* Global exported symbol: fd_transpile_export */
  syms[ sym_cnt++ ] = (fd_elf64_sym){
    .st_name  = fd_elf_strtab_append( &strtab, export_sym_name ),
    .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_GLOBAL, FD_ELF_STT_OBJECT ),
    .st_shndx = sec_idx_rodata,
    .st_value = 0UL,
    .st_size  = sizeof(fd_transpile_export_t)
  };

  /* Map external symbols for relocations */
  uint raw_to_symtab[ 256 ] = {0};

  for( ulong i = 0UL; i < reloc_cnt; i++ ) {
    uint raw_sym = FD_ELF64_R_SYM( t->reloc[ i ].r_info );
    uint sym_idx = 0U;

    if( raw_sym == FD_VM_TRANSPILE_SYM_TEXT ) {
      sym_idx = 1U;
    } else if( raw_sym == FD_VM_TRANSPILE_SYM_RODATA ) {
      sym_idx = 2U;
      text_relas[ i ].r_addend += (long)tables_off;
    } else if( raw_sym < 256U && raw_to_symtab[ raw_sym ] ) {
      sym_idx = raw_to_symtab[ raw_sym ];
    } else {
      char const * sym_name = NULL;
      if( raw_sym == FD_VM_TRANSPILE_SYM_MMU_TRANSLATE ) {
        sym_name = "fd_vm_transpiled_mmu_translate";
      } else if( raw_sym == FD_VM_TRANSPILE_SYM_FRAME_INIT ) {
        sym_name = "fd_vm_transpiled_frame_init";
      } else if( raw_sym >= FD_VM_TRANSPILE_SYM_MAX &&
                 raw_sym <  FD_VM_TRANSPILE_SYM_MAX + FD_SBPF_SYSCALLS_SLOT_CNT &&
                 syscalls && syscalls[ raw_sym - FD_VM_TRANSPILE_SYM_MAX ].func ) {
        ulong slot = (ulong)( raw_sym - FD_VM_TRANSPILE_SYM_MAX );
        sym_name = syscall_c_sym_name( syscalls[ slot ].func );
        if( FD_UNLIKELY( !sym_name ) ) {
          FD_LOG_WARNING(( "syscall %s has no known C symbol", syscalls[ slot ].name ));
        }
      }
      if( FD_UNLIKELY( !sym_name ) ) {
        FD_LOG_WARNING(( "relocation %lu against unknown symbol %u", i, raw_sym ));
        free( strtab_buf );
        free( syms );
        free( text_relas );
        return 0UL;
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
      if( raw_sym < 256U ) raw_to_symtab[ raw_sym ] = sym_idx;
    }

    text_relas[ i ].r_info = FD_ELF64_R_INFO( sym_idx, FD_ELF64_R_TYPE( t->reloc[ i ].r_info ) );
  }

  if( FD_UNLIKELY( strtab.err ) ) {
    FD_LOG_WARNING(( "ELF string table overflow" ));
    free( strtab_buf );
    free( syms );
    free( text_relas );
    return 0UL;
  }

  /* .data.rel.ro: export metadata followed by transpiler tables */
  uchar * rodata = malloc( rodata_sz );
  ulong rodata_rela_cnt = 1UL + t->rodata_reloc_cnt;
  fd_elf64_rela * rodata_relas = malloc( rodata_rela_cnt * sizeof(fd_elf64_rela) );
  if( FD_UNLIKELY( !rodata || !rodata_relas ) ) {
    FD_LOG_WARNING(( "malloc failed" ));
    free( rodata );
    free( rodata_relas );
    free( strtab_buf );
    free( syms );
    free( text_relas );
    return 0UL;
  }
  memset( rodata, 0, rodata_sz );
  fd_transpile_export_t * export = (fd_transpile_export_t *)rodata;
  export->abi_version = FD_TRANSPILE_ABI_VERSION;
  export->struct_size = sizeof(fd_transpile_export_t);
  export->exec        = NULL; /* materialized by relocation */
  export->meta        = t->meta;
  memcpy( rodata + tables_off, t->rodata, t->rodata_sz );

  /* .rela.data.rel.ro: export.exec, then basic block jump table entries */
  rodata_relas[ 0 ] = (fd_elf64_rela){
    .r_offset = (ulong)offsetof( fd_transpile_export_t, exec ),
    .r_info   = FD_ELF64_R_INFO( 1U /* .text */, FD_ELF_R_X86_64_64 ),
    .r_addend = (long)t->entrypoint_off
  };
  for( ulong i = 0UL; i < t->rodata_reloc_cnt; i++ ) {
    if( FD_UNLIKELY( FD_ELF64_R_SYM( t->rodata_reloc[ i ].r_info ) != FD_VM_TRANSPILE_SYM_TEXT ) ) {
      FD_LOG_WARNING(( "unsupported rodata relocation %lu", i ));
      free( rodata );
      free( rodata_relas );
      free( strtab_buf );
      free( syms );
      free( text_relas );
      return 0UL;
    }
    rodata_relas[ 1UL + i ] = (fd_elf64_rela){
      .r_offset = tables_off + t->rodata_reloc[ i ].r_offset,
      .r_info   = FD_ELF64_R_INFO( 1U /* .text */, FD_ELF64_R_TYPE( t->rodata_reloc[ i ].r_info ) ),
      .r_addend = t->rodata_reloc[ i ].r_addend
    };
  }

  static char const comment_data[] = "Firedancer sBPF transpiler";

  fd_elf_sec_t sec[ 10 ] = {
    { .name = "", .type = FD_ELF_SHT_NULL },
    { .name = ".text", .type = FD_ELF_SHT_PROGBITS, .flags = FD_ELF_SHF_ALLOC | FD_ELF_SHF_EXECINSTR,
      .align = 16UL, .data = t->code, .sz = t->code_sz },
    { .name = ".rela.text", .type = FD_ELF_SHT_RELA, .flags = FD_ELF_SHF_INFO_LINK,
      .align = 8UL, .entsize = sizeof(fd_elf64_rela), .link = sec_idx_symtab, .info = sec_idx_text,
      .data = reloc_cnt ? text_relas : NULL, .sz = reloc_cnt * sizeof(fd_elf64_rela) },
    { .name = ".data.rel.ro", .type = FD_ELF_SHT_PROGBITS, .flags = FD_ELF_SHF_ALLOC | FD_ELF_SHF_WRITE,
      .align = 8UL, .data = rodata, .sz = rodata_sz },
    { .name = ".rela.data.rel.ro", .type = FD_ELF_SHT_RELA, .flags = FD_ELF_SHF_INFO_LINK,
      .align = 8UL, .entsize = sizeof(fd_elf64_rela), .link = sec_idx_symtab, .info = sec_idx_rodata,
      .data = rodata_relas, .sz = rodata_rela_cnt * sizeof(fd_elf64_rela) },
    { .name = ".comment", .type = FD_ELF_SHT_PROGBITS, .align = 1UL, .entsize = 1UL,
      .data = comment_data, .sz = sizeof(comment_data) },
    { .name = ".note.GNU-stack", .type = FD_ELF_SHT_PROGBITS, .align = 1UL },
    { .name = ".symtab", .type = FD_ELF_SHT_SYMTAB, .align = 8UL, .entsize = sizeof(fd_elf64_sym),
      .link = sec_idx_strtab, .info = first_global, .data = syms, .sz = sym_cnt * sizeof(fd_elf64_sym) },
    { .name = ".strtab", .type = FD_ELF_SHT_STRTAB, .align = 1UL, .data = strtab.buf, .sz = strtab.sz },
    { .name = ".shstrtab", .type = FD_ELF_SHT_STRTAB, .align = 1UL }
  };

  ulong elf_sz = elf_max;
  uchar * res = elf_write( elf, &elf_sz, sec, 10UL );

  free( rodata );
  free( rodata_relas );
  free( strtab_buf );
  free( syms );
  free( text_relas );

  if( FD_UNLIKELY( !res ) ) return 0UL;
  return elf_sz;
}

#if FD_HAS_HOSTED

#define FD_AR_HDR_SZ (60UL)

/* ar_hdr writes a 60 byte ar member header to f */

static int
ar_hdr( FILE *       f,
        char const * name,
        ulong        sz ) {
  char hdr[ FD_AR_HDR_SZ+1UL ];
  int n = snprintf( hdr, sizeof(hdr), "%-16s%-12lu%-6lu%-6lu%-8o%-10lu`\n", name, 0UL, 0UL, 0UL, 0644U, sz );
  if( FD_UNLIKELY( n!=(int)FD_AR_HDR_SZ ) ) return -1;
  return fwrite( hdr, 1UL, FD_AR_HDR_SZ, f )==FD_AR_HDR_SZ ? 0 : -1;
}

static int
ar_u32be( FILE * f,
          ulong  x ) {
  uchar b[4] = { (uchar)(x>>24), (uchar)(x>>16), (uchar)(x>>8), (uchar)x };
  return fwrite( b, 1UL, 4UL, f )==4UL ? 0 : -1;
}

static int
ar_pad( FILE * f,
        ulong  sz ) {
  if( !(sz&1UL) ) return 0;
  return fputc( '\n', f )=='\n' ? 0 : -1;
}

int
fd_transpile_export_ar( char const *         dir,
                        char const *         ar_name,
                        char const * const * names,
                        char const * const * syms,
                        ulong                cnt ) {
  char ar_path [ PATH_MAX ];
  char tmp_path[ PATH_MAX ];
  if( FD_UNLIKELY( !fd_cstr_printf_check( ar_path,  sizeof(ar_path),  NULL, "%s/%s",     dir, ar_name ) ||
                   !fd_cstr_printf_check( tmp_path, sizeof(tmp_path), NULL, "%s/%s.tmp", dir, ar_name ) ) ) {
    FD_LOG_WARNING(( "archive path too long" ));
    return -1;
  }

  /* Size the symbol index and long name table */

  ulong sym_cnt    = 0UL;
  ulong sym_str_sz = 0UL;
  ulong names_sz   = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    if( syms[ i ] ) {
      sym_cnt++;
      sym_str_sz += strlen( syms[ i ] )+1UL;
    }
    names_sz += strlen( names[ i ] )+2UL; /* "name/\n" */
  }
  ulong symtab_sz = 4UL + 4UL*sym_cnt + sym_str_sz;

  ulong member0_off = 8UL + FD_AR_HDR_SZ + fd_ulong_align_up( symtab_sz, 2UL )
                          + FD_AR_HDR_SZ + fd_ulong_align_up( names_sz,  2UL );
  if( FD_UNLIKELY( member0_off + cnt*FD_AR_HDR_SZ > UINT_MAX ) ) {
    FD_LOG_WARNING(( "archive too large" ));
    return -1;
  }

  FILE * f = fopen( tmp_path, "wb" );
  if( FD_UNLIKELY( !f ) ) {
    FD_LOG_WARNING(( "fopen(%s) failed (%i-%s)", tmp_path, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  int err = 0;
  err |= fwrite( "!<thin>\n", 1UL, 8UL, f )!=8UL;

  /* Symbol index: count, member header offsets, symbol names */

  err |= ar_hdr( f, "/", symtab_sz );
  err |= ar_u32be( f, sym_cnt );
  for( ulong i=0UL; i<cnt; i++ ) {
    if( syms[ i ] ) err |= ar_u32be( f, member0_off + i*FD_AR_HDR_SZ );
  }
  for( ulong i=0UL; i<cnt; i++ ) {
    if( syms[ i ] ) err |= fwrite( syms[ i ], 1UL, strlen( syms[ i ] )+1UL, f )!=strlen( syms[ i ] )+1UL;
  }
  err |= ar_pad( f, symtab_sz );

  /* Long name table (thin archive members are always named via it) */

  err |= ar_hdr( f, "//", names_sz );
  for( ulong i=0UL; i<cnt; i++ ) {
    err |= fprintf( f, "%s/\n", names[ i ] )<0;
  }
  err |= ar_pad( f, names_sz );

  /* Member headers (no content) */

  ulong name_off = 0UL;
  for( ulong i=0UL; !err && i<cnt; i++ ) {
    char member_path[ PATH_MAX ];
    struct stat st;
    if( FD_UNLIKELY( !fd_cstr_printf_check( member_path, sizeof(member_path), NULL, "%s/%s", dir, names[ i ] ) ||
                     stat( member_path, &st ) ) ) {
      FD_LOG_WARNING(( "stat(%s) failed (%i-%s)", member_path, errno, fd_io_strerror( errno ) ));
      err = 1;
      break;
    }
    char member_name[ 17 ];
    FD_TEST( fd_cstr_printf_check( member_name, sizeof(member_name), NULL, "/%lu", name_off ) );
    err |= ar_hdr( f, member_name, (ulong)st.st_size );
    name_off += strlen( names[ i ] )+2UL;
  }

  err |= fclose( f )!=0;
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "failed to write %s", tmp_path ));
    unlink( tmp_path );
    return -1;
  }
  if( FD_UNLIKELY( rename( tmp_path, ar_path ) ) ) {
    FD_LOG_WARNING(( "rename(%s,%s) failed (%i-%s)", tmp_path, ar_path, errno, fd_io_strerror( errno ) ));
    unlink( tmp_path );
    return -1;
  }
  return 0;
}

static int
cmp_str_ptr( void const * a, void const * b ) {
  char const * const * sa = (char const * const *)a;
  char const * const * sb = (char const * const *)b;
  return strcmp( *sa, *sb );
}

int
fd_transpiler_export_archive( char const * obj_dir ) {
  if( FD_UNLIKELY( !obj_dir || !obj_dir[0] ) ) {
    FD_LOG_WARNING(( "Invalid obj_dir" ));
    return -1;
  }

  DIR * dir = opendir( obj_dir );
  if( FD_UNLIKELY( !dir ) ) {
    FD_LOG_WARNING(( "opendir(%s) failed (%i-%s)", obj_dir, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  ulong max_entries = 1024UL;
  char ** obj_names = malloc( max_entries * sizeof(char *) );
  if( FD_UNLIKELY( !obj_names ) ) {
    closedir( dir );
    FD_LOG_WARNING(( "malloc failed" ));
    return -1;
  }

  ulong obj_cnt = 0UL;
  struct dirent * de;
  while( (de = readdir( dir )) ) {
    char const * name = de->d_name;
    ulong len = strlen( name );
    /* Match 'fd_transpiled_*.o' except 'fd_transpiled_export.o' */
    if( len > 16UL &&
        !memcmp( name, "fd_transpiled_", 14UL ) &&
        !strcmp( name + len - 2UL, ".o" ) &&
        strcmp( name, "fd_transpiled_export.o" ) != 0 ) {

      if( FD_UNLIKELY( obj_cnt >= max_entries ) ) {
        max_entries *= 2UL;
        char ** new_names = realloc( obj_names, max_entries * sizeof(char *) );
        if( FD_UNLIKELY( !new_names ) ) {
          closedir( dir );
          for( ulong i=0UL; i<obj_cnt; i++ ) free( obj_names[i] );
          free( obj_names );
          return -1;
        }
        obj_names = new_names;
      }
      char * dup = strdup( name );
      if( FD_UNLIKELY( !dup ) ) {
        closedir( dir );
        for( ulong i=0UL; i<obj_cnt; i++ ) free( obj_names[i] );
        free( obj_names );
        return -1;
      }
      obj_names[ obj_cnt++ ] = dup;
    }
  }
  closedir( dir );

  /* Sort entries alphabetically */
  qsort( obj_names, obj_cnt, sizeof(char *), cmp_str_ptr );

  /* Build symbol names: replace "fd_transpiled_" with "fd_transpiled_ext_" and strip ".o" */
  char ** sym_names = malloc( (obj_cnt + 1UL) * sizeof(char *) );
  char ** all_names = malloc( (obj_cnt + 1UL) * sizeof(char *) );
  char ** all_syms  = malloc( (obj_cnt + 1UL) * sizeof(char *) );
  if( FD_UNLIKELY( !sym_names || !all_names || !all_syms ) ) {
    for( ulong i=0UL; i<obj_cnt; i++ ) free( obj_names[i] );
    free( obj_names );
    free( sym_names );
    free( all_names );
    free( all_syms );
    return -1;
  }

  ulong sym_cnt_ok = 0UL;
  for( ; sym_cnt_ok < obj_cnt; sym_cnt_ok++ ) {
    ulong len = strlen( obj_names[ sym_cnt_ok ] );
    /* name without "fd_transpiled_" and without ".o" */
    ulong core_len = len - 14UL - 2UL;
    char sym[ 320 ];
    if( FD_UNLIKELY( !fd_cstr_printf_check( sym, sizeof(sym), NULL, "fd_transpiled_ext_%.*s", (int)core_len, obj_names[ sym_cnt_ok ] + 14UL ) ) ) break;
    sym_names[ sym_cnt_ok ] = strdup( sym );
    if( FD_UNLIKELY( !sym_names[ sym_cnt_ok ] ) ) break;
  }
  if( FD_UNLIKELY( sym_cnt_ok < obj_cnt ) ) {
    FD_LOG_WARNING(( "failed to derive symbol name for %s", obj_names[ sym_cnt_ok ] ));
    for( ulong i=0UL; i<obj_cnt;     i++ ) free( obj_names[i] );
    for( ulong i=0UL; i<sym_cnt_ok;  i++ ) free( sym_names[i] );
    free( obj_names );
    free( sym_names );
    free( all_names );
    free( all_syms );
    return -1;
  }

  /* 1. Generate fd_transpiled_export.o */
  /* Contains NULL-terminated array: fd_transpile_export_t const * const fd_transpiled_ext[] */

  ulong data_sz = (obj_cnt + 1UL) * sizeof(ulong);
  uchar * data = calloc( 1UL, data_sz );
  fd_elf64_rela * relas = calloc( fd_ulong_max( obj_cnt, 1UL ), sizeof(fd_elf64_rela) );
  ulong sym_cnt = 3UL + obj_cnt; /* 0: undef, 1: .data.rel.ro, 2: fd_transpiled_ext, 3..: externals */
  fd_elf64_sym * esyms = calloc( sym_cnt, sizeof(fd_elf64_sym) );
  ulong str_cap = 128UL;
  for( ulong i=0UL; i<obj_cnt; i++ ) str_cap += strlen( sym_names[ i ] ) + 1UL;
  char * strs = malloc( str_cap );

  int export_ok = 0;
  if( FD_LIKELY( data && relas && esyms && strs ) ) {
    ushort const sec_idx_data   = 1;
    ushort const sec_idx_symtab = 4;
    ushort const sec_idx_strtab = 5;

    fd_elf_strtab_t strtab;
    fd_elf_strtab_init( &strtab, strs, str_cap );

    esyms[ 1 ] = (fd_elf64_sym){
      .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_LOCAL, FD_ELF_STT_SECTION ),
      .st_shndx = sec_idx_data
    };
    esyms[ 2 ] = (fd_elf64_sym){
      .st_name  = fd_elf_strtab_append( &strtab, "fd_transpiled_ext" ),
      .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_GLOBAL, FD_ELF_STT_OBJECT ),
      .st_shndx = sec_idx_data,
      .st_value = 0UL,
      .st_size  = data_sz
    };
    for( ulong i=0UL; i<obj_cnt; i++ ) {
      esyms[ 3UL + i ] = (fd_elf64_sym){
        .st_name  = fd_elf_strtab_append( &strtab, sym_names[ i ] ),
        .st_info  = FD_ELF64_ST_INFO( FD_ELF_STB_GLOBAL, FD_ELF_STT_OBJECT ),
        .st_shndx = FD_ELF_SHN_UNDEF
      };
      relas[ i ] = (fd_elf64_rela){
        .r_offset = i * sizeof(ulong),
        .r_info   = FD_ELF64_R_INFO( 3UL + i, FD_ELF_R_X86_64_64 ),
        .r_addend = 0L
      };
    }

    fd_elf_sec_t sec[ 7 ] = {
      { .name = "", .type = FD_ELF_SHT_NULL },
      { .name = ".data.rel.ro", .type = FD_ELF_SHT_PROGBITS, .flags = FD_ELF_SHF_ALLOC | FD_ELF_SHF_WRITE,
        .align = 64UL, .data = data, .sz = data_sz },
      { .name = ".rela.data.rel.ro", .type = FD_ELF_SHT_RELA, .flags = FD_ELF_SHF_INFO_LINK,
        .align = 8UL, .entsize = sizeof(fd_elf64_rela), .link = sec_idx_symtab, .info = sec_idx_data,
        .data = obj_cnt ? relas : NULL, .sz = obj_cnt * sizeof(fd_elf64_rela) },
      { .name = ".note.GNU-stack", .type = FD_ELF_SHT_PROGBITS, .align = 1UL },
      { .name = ".symtab", .type = FD_ELF_SHT_SYMTAB, .align = 8UL, .entsize = sizeof(fd_elf64_sym),
        .link = sec_idx_strtab, .info = 2U /* first global */, .data = esyms, .sz = sym_cnt * sizeof(fd_elf64_sym) },
      { .name = ".strtab", .type = FD_ELF_SHT_STRTAB, .align = 1UL, .data = strtab.buf, .sz = strtab.sz },
      { .name = ".shstrtab", .type = FD_ELF_SHT_STRTAB, .align = 1UL }
    };

    ulong export_elf_max = 65536UL + data_sz + obj_cnt * sizeof(fd_elf64_rela) + str_cap;
    uchar * export_elf = malloc( export_elf_max );
    if( export_elf ) {
      ulong export_elf_sz = export_elf_max;
      if( elf_write( export_elf, &export_elf_sz, sec, 7UL ) ) {
        char export_path[ PATH_MAX ];
        if( fd_cstr_printf_check( export_path, sizeof(export_path), NULL, "%s/fd_transpiled_export.o", obj_dir ) ) {
          FILE * f = fopen( export_path, "wb" );
          if( f ) {
            int write_ok = fwrite( export_elf, 1UL, export_elf_sz, f ) == export_elf_sz;
            int close_ok = !fclose( f );
            export_ok = write_ok && close_ok;
          }
        }
      }
      free( export_elf );
    }
  }

  free( strs );
  free( esyms );
  free( relas );
  free( data );

  if( FD_UNLIKELY( !export_ok ) ) {
    FD_LOG_WARNING(( "failed to generate fd_transpiled_export.o" ));
    for( ulong i=0UL; i<obj_cnt; i++ ) {
      free( obj_names[ i ] );
      free( sym_names[ i ] );
    }
    free( obj_names );
    free( sym_names );
    free( all_names );
    free( all_syms );
    return -1;
  }

  /* 2. Generate libfd_transpiled.a thin archive */
  all_names[ 0 ] = "fd_transpiled_export.o";
  all_syms [ 0 ] = "fd_transpiled_ext";
  for( ulong i = 0UL; i < obj_cnt; i++ ) {
    all_names[ 1UL + i ] = obj_names[ i ];
    all_syms [ 1UL + i ] = sym_names[ i ];
  }

  int ar_res = fd_transpile_export_ar( obj_dir, "libfd_transpiled.a",
                                           (char const * const *)all_names,
                                           (char const * const *)all_syms,
                                           obj_cnt + 1UL );

  for( ulong i=0UL; i<obj_cnt; i++ ) {
    free( obj_names[ i ] );
    free( sym_names[ i ] );
  }
  free( obj_names );
  free( sym_names );
  free( all_names );
  free( all_syms );

  return ar_res;
}

#endif /* FD_HAS_HOSTED */
