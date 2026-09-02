#define _GNU_SOURCE

#include "fd_exec_pmu.h"

#if FD_EXEC_PMU_HAS_PERF
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cpuid.h>
#endif

uint
fd_exec_pmu_amd_llc_miss_umask( uint family,
                                uint model ) {
  /* Event 43h is a core PMC.  These masks include near/far cache,
     near/far DRAM or MMIO, and (where present) extension memory, while
     excluding fills from local L2 and local L3. */

  /* Linux tools/perf/pmu-events AMD mappings classify these Family 19h
     models as Zen 3.  Later Family 19h models are Zen 4. */
  if( family==0x19U ) {
    if( model<0x10U ||
        (model>=0x20U && model<=0x2fU) ||
        (model>=0x40U && model<=0x5fU) ) return 0x5cU;
    return 0xdcU;
  }

  /* Known Zen 5 Family 1Ah model groups. */
  if( family==0x1aU ) {
    uint model_hi = model>>4;
    if( model<0x10U || model_hi==0x1U || model_hi==0x2U ||
                        model_hi==0x4U || model_hi==0x6U ||
                        model_hi==0x7U ) return 0xdcU;
  }

  return 0U;
}

static uint
fd_exec_pmu_detect_amd_llc_miss_umask( void ) {
#if FD_EXEC_PMU_HAS_PERF
  uint eax, ebx, ecx, edx;
  if( FD_UNLIKELY( !__get_cpuid( 0U, &eax, &ebx, &ecx, &edx ) ) ) return 0U;
  if( FD_UNLIKELY( ebx!=0x68747541U || edx!=0x69746e65U || ecx!=0x444d4163U ) ) return 0U; /* AuthenticAMD */
  if( FD_UNLIKELY( !__get_cpuid( 1U, &eax, &ebx, &ecx, &edx ) ) ) return 0U;

  uint base_family = (eax>>8) &0xfU;
  uint ext_family  = (eax>>20)&0xffU;
  uint base_model  = (eax>>4) &0xfU;
  uint ext_model   = (eax>>16)&0xfU;
  uint family      = base_family + fd_uint_if( base_family==0xfU, ext_family, 0U );
  uint model       = base_model  | fd_uint_if( base_family==0x6U || base_family==0xfU, ext_model<<4, 0U );
  return fd_exec_pmu_amd_llc_miss_umask( family, model );
#else
  return 0U;
#endif
}

void
fd_exec_pmu_reset( fd_exec_pmu_t * pmu ) {
  pmu->magic     = FD_EXEC_PMU_MAGIC;
  pmu->enabled   = 0;
  pmu->txn_valid = 0;
  for( ulong i=0UL; i<FD_EXEC_PMU_EVENT_CNT; i++ ) {
    pmu->fd  [ i ] = -1;
    pmu->page[ i ] = NULL;
    pmu->prev[ i ] = 0UL;
  }
}

#if FD_EXEC_PMU_HAS_PERF
static void
fd_exec_pmu_fini( fd_exec_pmu_t * pmu ) {
  for( ulong i=0UL; i<FD_EXEC_PMU_EVENT_CNT; i++ ) {
    if( pmu->page[ i ] ) {
      munmap( pmu->page[ i ], FD_SHMEM_NORMAL_PAGE_SZ );
      pmu->page[ i ] = NULL;
    }
    if( pmu->fd[ i ]>=0 ) {
      close( pmu->fd[ i ] );
      pmu->fd[ i ] = -1;
    }
  }
  pmu->enabled = 0;
}
#endif

static int
fd_exec_pmu_open( fd_exec_pmu_t * pmu,
                  uint            llc_miss_umask ) {
#if FD_EXEC_PMU_HAS_PERF
  static ulong const type[ FD_EXEC_PMU_EVENT_CNT ] = {
    PERF_TYPE_HARDWARE,
    PERF_TYPE_HARDWARE,
    PERF_TYPE_RAW
  };
  ulong const config[ FD_EXEC_PMU_EVENT_CNT ] = {
    PERF_COUNT_HW_CPU_CYCLES,
    PERF_COUNT_HW_INSTRUCTIONS,
    ((ulong)llc_miss_umask<<8) | 0x43UL /* LS_DMND_FILLS_FROM_SYS */
  };

  /* pid=0,cpu=-1 creates a task-scoped core-PMU event.  perf switches
     this PMU context with this thread, and exclude_kernel/exclude_hv
     prevents interrupt and host activity from being charged.  Other
     cores' requests therefore do not increment this LLC-miss counter.
     They can still evict shared cache lines and cause genuine misses in
     this thread.  Callers only enable this path for CPU-pinned tiles. */
  fd_exec_pmu_reset( pmu );
  int group_fd = -1;
  for( ulong i=0UL; i<FD_EXEC_PMU_EVENT_CNT; i++ ) {
    struct perf_event_attr attr;
    fd_memset( &attr, 0, sizeof(attr) );
    attr.type           = (uint)type[ i ];
    attr.size           = sizeof(attr);
    attr.config         = config[ i ];
    attr.disabled       = (i==0UL);
    attr.pinned         = (i==0UL);
    attr.exclude_kernel = 1U;
    attr.exclude_hv     = 1U;

    int fd = (int)syscall( __NR_perf_event_open, &attr, 0, -1, group_fd, PERF_FLAG_FD_CLOEXEC );
    if( FD_UNLIKELY( fd<0 ) ) goto fail;
    pmu->fd[ i ] = fd;
    if( i==0UL ) group_fd = fd;

    void * page = mmap( NULL, FD_SHMEM_NORMAL_PAGE_SZ, PROT_READ, MAP_SHARED, fd, 0 );
    if( FD_UNLIKELY( page==MAP_FAILED ) ) {
      pmu->page[ i ] = NULL;
      goto fail;
    }
    pmu->page[ i ] = page;
    if( FD_UNLIKELY( !pmu->page[ i ]->cap_user_rdpmc ) ) {
      errno = ENOTSUP;
      goto fail;
    }
  }

  if( FD_UNLIKELY( ioctl( group_fd, PERF_EVENT_IOC_RESET,  PERF_IOC_FLAG_GROUP ) ) ) goto fail;
  if( FD_UNLIKELY( ioctl( group_fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP ) ) ) goto fail;
  pmu->enabled = 1;
  return 1;

fail:
  {
    int err = errno;
    fd_exec_pmu_fini( pmu );
    errno = err;
  }
  return 0;
#else
  (void)pmu;
  (void)llc_miss_umask;
  return 0;
#endif
}

int
fd_exec_pmu_init( fd_exec_pmu_t * pmu,
                  int             is_pinned ) {
  fd_exec_pmu_reset( pmu );
  if( FD_UNLIKELY( !is_pinned ) ) return 0;

  uint llc_miss_umask = fd_exec_pmu_detect_amd_llc_miss_umask();
  if( FD_UNLIKELY( !llc_miss_umask ) ) return 0;
  return fd_exec_pmu_open( pmu, llc_miss_umask ) ? 1 : -1;
}
