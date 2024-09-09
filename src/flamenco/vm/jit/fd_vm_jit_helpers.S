.intel_syntax noprefix

.globl fd_jit_vm_translate_ro
.type  fd_jit_vm_translate_ro,@function
fd_jit_vm_translate_ro:
    # rdi contains the virtual address
    # esi contains the size of the access minus one

    # edx contains the segment offset
    mov edx, edi

    # Is access aligned?
    and edi, esi
    test edi, esi
    jne sigsegv

    # Is access fully within segment?
    add esi, edx
    jc sigsegv

    # edi contains the segment index
    shr rdi, 32

    # Is segment index in bounds?
    cmp edi, fs:[fd_jit_segment_cnt@tpoff]
    jae sigsegv

    # Is segment offset in bounds?
    cmp esi, fs:[rdi*4 + fd_jit_mem_ro_sz@tpoff]
    ja sigsegv

    # rdx contains the host address
    add rdx, fs:[rdi*8 + fd_jit_mem_base@tpoff]
    ret
.size fd_jit_vm_translate_ro,.-fd_jit_vm_translate_ro

.globl fd_jit_vm_translate_rw
.type  fd_jit_vm_translate_rw,@function
fd_jit_vm_translate_rw:
    # rdi contains the virtual address
    # esi contains the size of the access minus one

    # edx contains the segment offset
    mov edx, edi

    # Is access aligned?
    and edi, esi
    test edi, esi
    jne sigsegv

    # Is access fully within segment?
    add esi, edx
    jc sigsegv

    # edi contains the segment index
    shr rdi, 32

    # Is segment index in bounds?
    cmp edi, fs:[fd_jit_segment_cnt@tpoff]
    jae sigsegv

    # Is segment offset in bounds?
    cmp esi, fs:[rdi*4 + fd_jit_mem_rw_sz@tpoff]
    ja sigsegv

    # rdx contains the host address
    add rdx, fs:[rdi*8 + fd_jit_mem_base@tpoff]
    ret
.size fd_jit_vm_translate_rw,.-fd_jit_vm_translate_rw

# Trampoline via a local symbol reduces the code footprint of the
# fd_jit_vm_translate hot path
sigsegv:
    ud2 # TODO
