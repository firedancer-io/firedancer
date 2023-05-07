#define _DARWIN_C_SOURCE

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <pthread.h>
#include <mach/thread_policy.h>
#include <mach/thread_act.h>
#include <mach/mach_init.h>
#include "../fd_util.h"

#define CPU_SETSIZE 32
#define SYSCTL_CORE_COUNT   "machdep.cpu.core_count"

kern_return_t
thread_policy_set( thread_act_t thread, thread_policy_flavor_t flavor, thread_policy_t policy_info, mach_msg_type_number_t count );

typedef struct cpu_set_t
{
    unsigned int count;
} cpu_set_t;

void
CPU_ZERO( cpu_set_t *arg ) { arg->count = 0; }

void
CPU_SET( int cpu, cpu_set_t *arg ) { arg->count |= (1 << cpu); }

unsigned int
CPU_ISSET( size_t cpu, cpu_set_t *arg ) { return arg->count & (1 << cpu); }

void
CPU_CLR( size_t cpu, cpu_set_t *arg ) { arg->count = arg->count & ~(1 << cpu); }

unsigned long 
CPU_COUNT( cpu_set_t *set ) {
    unsigned long i, count = 0;
    for (i = 0; i < CPU_SETSIZE; i++)
    {
        if (CPU_ISSET(i, set))
        {
            count++;
        }
    }
    return count;
}

int
sched_getaffinity( pid_t pid, size_t cpu_size, cpu_set_t *cpu_set ) {
  (void)pid;
  (void)cpu_size;
  int32_t core_count = 0;
  size_t  len = sizeof(core_count);
  int ret = sysctlbyname(SYSCTL_CORE_COUNT, &core_count, &len, 0, 0);
  if (ret) {
    return -1;
  }
  cpu_set->count = 0;
  for (int i = 0; i < core_count; i++) {
    cpu_set->count |= (1 << i);
  }

  return 0;
}

int
sched_setaffinity( pid_t pid, size_t cpusetsize, cpu_set_t *set ) {
    (void)pid;
    (void)cpusetsize;

    thread_affinity_policy_data_t policy;
    policy.affinity_tag = (integer_t)(set->count + 1); /* non-null affinity tag */

    thread_policy_set( mach_thread_self(), THREAD_AFFINITY_POLICY, (thread_policy_t)&policy, 1 );
    return 0;
}

int
pthread_setaffinity_mac( ulong cpu_idx ) {
  thread_affinity_policy_data_t policy;
  policy.affinity_tag = (integer_t)(cpu_idx + 1);

  mach_port_t thread = pthread_mach_thread_np( pthread_self() );
  thread_policy_set( thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy, 1 );
  /* Don't bother returning error status here; this is best effort, and fails on some Macs
    (e.g. M1/M2). */
  return 0;
}
