pub use crate::generated::{
    fd_sbpf_calldests_t,
    fd_sbpf_syscalls_t,
    fd_sbpf_program_info_t,
    fd_sbpf_program_t,
};
pub use crate::generated::{
    fd_sbpf_program_align,
    fd_sbpf_program_footprint,
    fd_sbpf_program_new,
    fd_sbpf_program_load,
    fd_sbpf_program_delete,
    fd_sbpf_strerror,
};

extern "C" {
    pub fn fd_sbpf_program_get_info(
        program: *const fd_sbpf_program_t,
    ) -> *const fd_sbpf_program_info_t;
}
