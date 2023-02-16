#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

pub mod fd_ffi;
pub mod fd_shm_channel;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fd_ffi_sanity_check() {
        print!(
            "\n\n  *** Calling bindings for constant fd_ffi::FD_CNC_MAGIC: {:#X} ***  \n\n\n",
            fd_ffi::FD_CNC_MAGIC
        );
    }
}
