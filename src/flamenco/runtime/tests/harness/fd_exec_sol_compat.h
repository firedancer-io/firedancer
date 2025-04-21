#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_exec_sol_compat_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_exec_sol_compat_h

/* fd_exec_sol_compat.h provides APIs for running differential
   tests between Agave and Firedancer. */

#include <assert.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "../../../../ballet/nanopb/pb_encode.h"
#include "../../../../ballet/nanopb/pb_decode.h"

#include "../../fd_executor_err.h"
#include "../../../fd_flamenco.h"
#include "../../../features/fd_features.h"
#include "../../../../ballet/shred/fd_shred.h"

#include "fd_instr_harness.h"
#include "fd_txn_harness.h"
#include "fd_block_harness.h"
#include "fd_types_harness.h"
#include "fd_vm_harness.h"
#include "fd_pack_harness.h"
#include "fd_elf_harness.h"

#include "generated/elf.pb.h"
#include "generated/invoke.pb.h"
#include "generated/shred.pb.h"
#include "generated/vm.pb.h"
#include "generated/type.pb.h"

FD_PROTOTYPES_BEGIN

void
sol_compat_wksp_init( ulong wksp_page_sz );

void
sol_compat_fini( void );

void
sol_compat_check_wksp_usage( void );

fd_runtime_fuzz_runner_t *
sol_compat_setup_runner( void );

void
sol_compat_cleanup_runner( fd_runtime_fuzz_runner_t * runner );

int
sol_compat_instr_fixture( fd_runtime_fuzz_runner_t * runner,
                          uchar const *              in,
                          ulong                      in_sz );

int
sol_compat_txn_fixture( fd_runtime_fuzz_runner_t * runner,
                        uchar const *              in,
                        ulong                      in_sz );

int
sol_compat_elf_loader_fixture( fd_runtime_fuzz_runner_t * runner,
                               uchar const *              in,
                               ulong                      in_sz );

int
sol_compat_syscall_fixture( fd_runtime_fuzz_runner_t * runner,
                            uchar const *              in,
                            ulong                      in_sz );

int
sol_compat_vm_interp_fixture( fd_runtime_fuzz_runner_t * runner,
                              uchar const *              in,
                              ulong                      in_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_exec_sol_compat_h */
