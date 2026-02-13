#ifndef HEADER_fd_src_fdos_x86_fd_x86_msr_h
#define HEADER_fd_src_fdos_x86_fd_x86_msr_h

#define FD_X86_CR0_PE (1U<<0)
#define FD_X86_CR0_MP (1U<<1)
#define FD_X86_CR0_EM (1U<<2)
#define FD_X86_CR0_TS (1U<<3)
#define FD_X86_CR0_ET (1U<<4)
#define FD_X86_CR0_NE (1U<<5)
#define FD_X86_CR0_WP (1U<<16)
#define FD_X86_CR0_AM (1U<<18)
#define FD_X86_CR0_NW (1U<<29)
#define FD_X86_CR0_CD (1U<<30)
#define FD_X86_CR0_PG (1U<<31)

#define FD_X86_CR4_PAE    (1U<<5)
#define FD_X86_CR4_OSFXSR (1U<<9)

#define FD_X86_EFER_SCE (1U<< 0)
#define FD_X86_EFER_LME (1U<< 8)
#define FD_X86_EFER_LMA (1U<<10)
#define FD_X86_EFER_NX  (1U<<11)

#define FD_X86_MSR_STAR  0xc0000081
#define FD_X86_MSR_LSTAR 0xc0000082

#endif /* HEADER_fd_src_fdos_x86_fd_x86_msr_h */
