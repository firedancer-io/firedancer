#ifndef SOURCE_fd_src_util_shmem_fd_shmem_admin
#error "Do not compile this file directly"
#endif

/* NUMA API stubs reporting all functions as unavailable */

int
fd_numa_available( void ) {
  return 0;
}

int
fd_shmem_numa_cnt_private( void ) {
  return -ENOSYS;
}

int
fd_shmem_cpu_cnt_private( void ) {
  return -ENOSYS;
}

int
fd_numa_cpu_max_cnt( void ) {
  return -ENOSYS;
}

int
fd_numa_node_of_cpu( int cpu_idx ) {
  return -ENOSYS;
}
