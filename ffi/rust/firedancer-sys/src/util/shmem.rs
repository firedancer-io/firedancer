pub use crate::generated::FD_SHMEM_NAME_MAX;
pub use crate::generated::{
    fd_shmem_info_t,
    fd_shmem_join_info_t,
    fd_shmem_joinleave_func_t,
};
// User APIs
pub use crate::generated::{
    fd_shmem_join,
    fd_shmem_join_anonymous,
    fd_shmem_join_query_by_addr,
    fd_shmem_join_query_by_join,
    fd_shmem_join_query_by_name,
    fd_shmem_leave,
    fd_shmem_leave_anonymous,
};
// Administrative APIs
pub use crate::generated::{
    fd_shmem_acquire,
    fd_shmem_cpu_cnt,
    fd_shmem_cpu_idx,
    fd_shmem_create,
    fd_shmem_info,
    fd_shmem_name_len,
    fd_shmem_numa_cnt,
    fd_shmem_numa_idx,
    fd_shmem_numa_validate,
    fd_shmem_release,
    fd_shmem_unlink,
};
pub use crate::generated::{
    fd_cstr_to_shmem_lg_page_sz,
    fd_cstr_to_shmem_page_sz,
    fd_shmem_lg_page_sz_to_cstr,
    fd_shmem_page_sz_to_cstr,
};
