#ifndef HEADER_fd_src_fdos_x86_fd_x86_idt_h
#define HEADER_fd_src_fdos_x86_fd_x86_idt_h

#include "../../util/fd_util_base.h"

struct __attribute__((packed)) fd_x86_idt_gate {
  ushort offset_low;
  ushort selector;
  uchar  ist;
  uchar  type_attr;
  ushort offset_mid;
  uint   offset_high;
  uint   reserved;
};

typedef struct fd_x86_idt_gate fd_x86_idt_gate_t;

#endif /* HEADER_fd_src_fdos_x86_fd_x86_idt_h */
