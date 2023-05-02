#include "fd_elf_loader.h"
#include "fd_elf_types.h"
#include "../fd_sbpf_interp.h"
#include "../../ballet/fd_ballet.h"

ulong 
fd_elf_validate( uchar const *  elf_obj_content,
                 ulong          elf_obj_content_len ) {
  if( elf_obj_content_len < sizeof(fd_elf64_elf_hdr_t) ) {
    return FD_ELF_VALIDATE_ERR_INSUFF_CONTENT;
  }

  /* Validate header */
  fd_elf64_elf_hdr_t const * elf_hdr = (fd_elf64_elf_hdr_t const *)elf_obj_content;
 
  /* Validate header ident */
  fd_elf64_elf_hdr_ident_t ident = elf_hdr->e_ident;
  
  if( ident.ei_magic != ELF_MAGIC ) {
    return FD_ELF_VALIDATE_ERR;
  }

  if( ident.ei_class != ELFCLASS_64 ) {
    return FD_ELF_VALIDATE_ERR;
  }

  if( ident.ei_data != ELFDATA_2LSB ) {
    return FD_ELF_VALIDATE_ERR;
  }

  if( ident.ei_version != EV_CURRENT ) {
    return FD_ELF_VALIDATE_ERR;
  }

  if( ident.ei_osabi != ELFOSABI_SYSV) {
    return FD_ELF_VALIDATE_ERR;
  }

  if( ident.ei_abiversion != 0) {
    return FD_ELF_VALIDATE_ERR;
  }

  if( elf_hdr->e_type != ET_DYN) {
    return FD_ELF_VALIDATE_ERR;
  }

  if( elf_hdr->e_machine != EM_BPF ) {
    return FD_ELF_VALIDATE_ERR;
  }

  if( elf_hdr->e_version != EV_CURRENT ) {
    return FD_ELF_VALIDATE_ERR;
  }
  
  if( elf_hdr->e_entry != 0x0 ) {
    return FD_ELF_VALIDATE_ERR;
  }
  
  if( elf_hdr->e_entry >= elf_obj_content_len ) {
    return FD_ELF_VALIDATE_ERR;
  }


  return FD_ELF_VALIDATE_SUCCESS;
}

ulong 
fd_elf_relocate_sbpf_program( uchar const *                       elf_obj_content,
                              FD_FN_UNUSED ulong                  elf_obj_content_len,
                              fd_elf64_relocated_sbfp_program_t * relocated_program ) {

  fd_elf64_elf_hdr_t const * elf_hdr = (fd_elf64_elf_hdr_t const *)elf_obj_content;

  //fd_elf64_program_hdr_t const * program_hdrs = (fd_elf64_program_hdr_t const *)(elf_obj_content + elf_hdr->e_phoff);

  fd_elf64_section_hdr_t const * section_hdrs = (fd_elf64_section_hdr_t const *)(elf_obj_content + elf_hdr->e_shoff);
  FD_LOG_NOTICE(( "e_type %d", elf_hdr->e_type ));
  FD_LOG_NOTICE(( "e_machine %d", elf_hdr->e_machine ));
  FD_LOG_NOTICE(( "e_version %d", elf_hdr->e_version ));
  FD_LOG_NOTICE(( "e_entry %lx", elf_hdr->e_entry ));
  FD_LOG_NOTICE(( "e_phoff %lu", elf_hdr->e_phoff ));
  FD_LOG_NOTICE(( "e_shoff %lu", elf_hdr->e_shoff ));
  FD_LOG_NOTICE(( "e_flags %d", elf_hdr->e_flags ));
  FD_LOG_NOTICE(( "e_ehsize %d", elf_hdr->e_ehsize ));
  FD_LOG_NOTICE(( "e_phentsize %d", elf_hdr->e_phentsize ));
  FD_LOG_NOTICE(( "e_phnum %d", elf_hdr->e_phnum ));
  FD_LOG_NOTICE(( "e_shnum %d", elf_hdr->e_shnum ));
  FD_LOG_NOTICE(( "e_shstrndx %d", elf_hdr->e_shstrndx ));
  fd_elf64_section_hdr_t const section_str_section_hdr = section_hdrs[elf_hdr->e_shstrndx];

  ulong text_section_found = 0; 
  ulong text_section_idx = 0;

  ulong rel_dyn_section_found = 0; 
  ulong rel_dyn_section_idx = 0;
  
  ulong dynsym_section_found = 0; 
  ulong dynsym_section_idx = 0;
  
  ulong dynstr_section_found = 0; 
  ulong dynstr_section_idx = 0;
  for( ulong i = 0; i < elf_hdr->e_shnum; i++ ) {
    fd_elf64_section_hdr_t const section_hdr = section_hdrs[i];

    char * section_name = (char *)(elf_obj_content + section_str_section_hdr.sh_offset + section_hdr.sh_name);
    FD_LOG_NOTICE(( "SECTION: %s", section_name ));
    
    if( strncmp(section_name, ELF_SECTION_TEXT, 5)==0 ) {
      // .text section
      relocated_program->text_section = (uchar *)elf_obj_content + section_hdr.sh_offset;
      relocated_program->text_section_len = section_hdr.sh_size;
      text_section_found = 1;
      text_section_idx = i;
    } else if( strncmp(section_name, ELF_SECTION_RODATA, 7)==0 ) {
      // .rodata section
      relocated_program->rodata_section = (uchar *)elf_obj_content + section_hdr.sh_offset;
      relocated_program->rodata_section_len = section_hdr.sh_size;
    } else if( strncmp(section_name, ELF_SECTION_REL_DYN, 8)==0 ) {
      rel_dyn_section_found = 1;
      rel_dyn_section_idx = i;
    } else if( strncmp(section_name, ELF_SECTION_DYNSYM, 7 )==0 ) {
      dynsym_section_found = 1;
      dynsym_section_idx = i;
    } else if( strncmp(section_name, ELF_SECTION_DYNSTR, 7 )==0 ) {
      dynstr_section_found = 1;
      dynstr_section_idx = i;
    } else {
      FD_LOG_WARNING(( "Unknown section: %s", section_name ));
    }
  }

  if( !text_section_found ) {
    return 1;
  }
  if( !rel_dyn_section_found ) {
    return 1;
  }
  if( !dynsym_section_found ) {
    return 1;
  }
  if( !dynstr_section_found ) {
    return 1;
  }

  fd_elf64_section_hdr_t const text_section_hdr = section_hdrs[text_section_idx];
  fd_elf64_section_hdr_t const dynsym_section_hdr = section_hdrs[dynsym_section_idx];
  fd_elf64_section_hdr_t const dynstr_section_hdr = section_hdrs[dynstr_section_idx];
  fd_elf64_section_hdr_t const rel_dyn_section_hdr = section_hdrs[rel_dyn_section_idx];
  fd_elf64_relocation_rel_t * relocations = (fd_elf64_relocation_rel_t *)(elf_obj_content + rel_dyn_section_hdr.sh_offset);
  fd_elf64_sym_tab_ent_t * sym_tab = (fd_elf64_sym_tab_ent_t *)(elf_obj_content + dynsym_section_hdr.sh_offset);
  ulong num_relocations = rel_dyn_section_hdr.sh_size / sizeof(fd_elf64_relocation_rel_t);

  for( ulong i = 0; i < num_relocations; i++ ) {
    fd_elf64_relocation_rel_t reloc = relocations[i];
    ulong rel_sym = reloc.r_info >> 32;
    ulong rel_type = reloc.r_info & 0xFFFFFFFFUL;

    fd_elf64_sym_tab_ent_t sym_tab_ent = sym_tab[rel_sym];

    FD_LOG_NOTICE(( "RELOC: %lu, info: %lx, off: %lx, sym: %lx, type: %lx", i, reloc.r_info, reloc.r_offset, rel_sym, rel_type ));
    switch( rel_type ) {
      case R_BPF_64_RELATIVE: 
      {
        // FIXME: Check section boundary condition
        if ( reloc.r_offset >= text_section_hdr.sh_offset && reloc.r_offset < text_section_hdr.sh_offset + text_section_hdr.sh_size ) {
          // We are in the .text section.
          fd_vm_sbpf_instr_t * instr = (fd_vm_sbpf_instr_t *)(elf_obj_content + reloc.r_offset);
          FD_LOG_NOTICE(( "RELOC INSTR %x", instr->opcode.raw ));
          if (instr->opcode.raw != FD_BPF_OP_LDQ) {
            return 1;
          }
        
          ulong ldq_imm = *(ulong *)(elf_obj_content + instr->imm);
          FD_LOG_NOTICE(( "RELOC REL %x %lx", instr->imm, ldq_imm ));
          

          fd_vm_sbpf_instr_t * addl_imm_instr = instr + 1;
          instr->imm = ldq_imm & 0xFFFFFFFF;
          addl_imm_instr->imm = ldq_imm >> 32;
        } else {
          ulong imm_offset = (*(ulong *)(elf_obj_content + reloc.r_offset)) >> 32;
          FD_LOG_NOTICE(( "RELOC QQQ %lx", imm_offset ));

          ulong imm_value = (*(ulong *)(elf_obj_content + imm_offset));
          FD_LOG_NOTICE(( "RELOC RRR %lx", imm_value ));
          ulong * reloc_addr = (ulong *)(elf_obj_content + reloc.r_offset);
          
          *reloc_addr = imm_value;
        }

        break;
      }
      case R_BPF_64_32:
      {
        fd_vm_sbpf_instr_t * instr = (fd_vm_sbpf_instr_t *)(elf_obj_content + reloc.r_offset);
        if( instr->imm==0xFFFFFFFF ) {
          ulong sym_type = (sym_tab_ent.st_info & 0xF);
          switch (sym_type) {
            case STT_NOTYPE: {
              // Syscall
              char const * call_name = (char const *)(elf_obj_content + dynstr_section_hdr.sh_offset + sym_tab_ent.st_name);
              ulong call_name_len = strlen(call_name);
              uint call_hash = fd_murmur3_hash_cstr_to_uint(call_name, call_name_len, 0);
              
              instr->imm = call_hash;
              break;
            }
            case STT_FUNC: {
              // FIXME: INCORRECT SEMANTIC,
              // Local calls
              char const * call_name = (char const *)(elf_obj_content + dynstr_section_hdr.sh_offset + sym_tab_ent.st_name);
              ulong call_name_len = strlen(call_name);
              uint call_hash = fd_murmur3_hash_cstr_to_uint(call_name, call_name_len, 0);
              
              instr->imm = call_hash;
              break;
            }
            default:
              return 1;
          }
        } else {
          FD_LOG_NOTICE(( "RELOC CALL NOT -1: imm: %u", instr->imm ));
        }
        FD_LOG_NOTICE(( "RELOC CALL INSTR %x %x", instr->opcode.raw, instr->imm ));
        break;
      }
      default:
        FD_LOG_NOTICE(( "UNKNOWN RELOC TYPE %lx", rel_type ));
        return 1;
    }
  }

  return 0;
}


