#ifndef HEADER_fd_src_vm_elf_fd_elf_loader_h
#define HEADER_fd_src_vm_elf_fd_elf_loader_h

#include "../../util/fd_util.h"

#include "fd_elf_types.h"

#define FD_ELF_VALIDATE_SUCCESS             (0)
#define FD_ELF_VALIDATE_ERR_INSUFF_CONTENT  (1)
#define FD_ELF_VALIDATE_ERR                 (0xFFFF)

ulong fd_elf_validate( uchar const *  elf_obj_content,
                       ulong          elf_obj_content_len );

ulong fd_elf_relocate_sbpf_program( uchar const *  elf_obj_content,
                                    ulong          elf_obj_content_len,
                                    fd_elf64_relocated_sbfp_program_t * relocated_program);

#endif /* HEADER_fd_src_vm_elf_fd_elf_loader_h */
