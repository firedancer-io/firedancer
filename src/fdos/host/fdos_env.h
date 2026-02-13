#ifndef HEADER_fd_src_fdos_host_fdos_host_h
#define HEADER_fd_src_fdos_host_fdos_host_h

#include "../kern/fdos_hypercall.h"
#include "../x86/fd_x86_gdt.h"
#include "../x86/fd_x86_idt.h"
#include "../x86/fd_x86_tss.h"
#include "../../util/wksp/fd_wksp.h"

struct fdos_env {
  fd_wksp_t * wksp_kern_meta;
  fd_wksp_t * wksp_kern_code;
  fd_wksp_t * wksp_kern_rodata;
  fd_wksp_t * wksp_kern_data;
  fd_wksp_t * wksp_kern_stack;
  fd_wksp_t * wksp_user_stack;

  /* Page table */
  ulong * pml4; /* in meta_wksp */
  ulong   pml4_gpaddr;

  /* Stack (kernel, user) */
  ulong   stack_kern_top_gvaddr;
  ulong   stack_kern_sz;
  ulong   stack_user_top_gvaddr;
  ulong   stack_user_sz;

  /* Kernel image */
  uchar * rodata;
  uchar * text;
  uchar * data;
  ulong   rodata_gvaddr;
  ulong   rodata_sz;
  ulong   text_gvaddr;
  ulong   text_sz;
  ulong   entry_gvaddr;
  ulong   data_gvaddr;
  ulong   data_sz;

  /* TSS (kernel, user) */
  fd_x86_tss64_t * tss_kern;
  fd_x86_tss64_t * tss_user;
  ulong            tss_kern_gpaddr;
  ulong            tss_user_gpaddr;

  /* GDT */
  ulong          gdt_gpaddr;
  fd_x86_gdt_t * gdt;

  /* Default interrupt handler */
  ulong int_handler_gvaddr; /* 256 bytes, 1 byte for each interrupt descriptor */

  /* IDT */
  ulong               idt_gpaddr;
  fd_x86_idt_gate_t * idt;

  /* Startup args */
  ulong              entry_args_gvaddr;
  fdos_kern_args_t * entry_args;

  /* Hypercalls */
  ulong                 hyper_args_gvaddr;
  fd_hypercall_args_t * hyper_args;
};

typedef struct fdos_env fdos_env_t;

void
fdos_env_img_load( fdos_env_t *  env,
                   uchar const * bin,
                   ulong         bin_sz );

/* fdos_env_create sets up all fdos kernel data structures
   needed to bootstrap a KVM ring 0 guest environment. */

fdos_env_t *
fdos_env_create( fdos_env_t *  env,
                 uchar const * kern_bin,
                 ulong         kern_bin_sz );

void
fdos_env_destroy( fdos_env_t * env );

#endif /* HEADER_fd_src_fdos_host_fdos_host_h */
