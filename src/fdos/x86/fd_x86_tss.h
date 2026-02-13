#ifndef HEADER_fd_src_fdos_x86_fd_x86_tss_h
#define HEADER_fd_src_fdos_x86_fd_x86_tss_h

#include "../../util/fd_util_base.h"

struct __attribute__((packed)) fd_x86_tss64 {
  uint   reserved0;
  ulong  rsp0;
  ulong  rsp1;
  ulong  rsp2;
  ulong  reserved1;
  ulong  ist1;
  ulong  ist2;
  ulong  ist3;
  ulong  ist4;
  ulong  ist5;
  ulong  ist6;
  ulong  ist7;
  ulong  reserved2;
  ushort reserved3;
  ushort iomap_base;
};

typedef struct fd_x86_tss64 fd_x86_tss64_t;

#endif /* HEADER_fd_src_fdos_x86_fd_x86_tss_h */
