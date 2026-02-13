#ifndef HEADER_fd_src_fdos_host_fdos_kvm_h
#define HEADER_fd_src_fdos_host_fdos_kvm_h

#include "fdos_env.h"
#include <linux/kvm.h>

void
fdos_hypercall_handler( fdos_env_t *     env,
                        int              vcpu_fd,
                        struct kvm_run * run );

int
fdos_kvm_run( fdos_env_t *     kern,
              struct kvm_run * kvm_run,
              int              vcpu_fd );

#endif /* HEADER_fd_src_fdos_host_fdos_kvm_h */
