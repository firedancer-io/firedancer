use std::ffi::c_void;

pub use crate::generated::{
    fd_sbpf_calldests_t,
    fd_sbpf_elf_info_t,
    fd_sbpf_elf_peek,
    fd_sbpf_program_align,
    fd_sbpf_program_delete,
    fd_sbpf_program_footprint,
    fd_sbpf_program_load,
    fd_sbpf_program_new,
    fd_sbpf_program_t,
    fd_sbpf_strerror,
    fd_sbpf_syscalls_t,
};

extern "C" {
    #[link_name = "fd_sbpf_syscalls_align_ext"]
    pub fn fd_sbpf_syscalls_align() -> usize;

    #[link_name = "fd_sbpf_syscalls_footprint_ext"]
    pub fn fd_sbpf_syscalls_footprint() -> usize;

    #[link_name = "fd_sbpf_syscalls_new_ext"]
    pub fn fd_sbpf_syscalls_new(_: *mut c_void) -> *mut fd_sbpf_syscalls_t;

    #[link_name = "fd_sbpf_syscalls_delete_ext"]
    pub fn fd_sbpf_syscalls_delete(_: *mut fd_sbpf_syscalls_t) -> *mut c_void;

    #[link_name = "fd_sbpf_syscalls_insert_ext"]
    pub fn fd_sbpf_syscalls_insert(
        syscalls: *mut fd_sbpf_syscalls_t,
        syscall_id: u32,
    ) -> *mut fd_sbpf_syscalls_t;
}
