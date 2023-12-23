use std::ffi::c_void;
use std::fmt::Debug;
use std::sync::Arc;

use firedancer_sys::ballet::*;
use solana_program_runtime::compute_budget::ComputeBudget;
use solana_program_runtime::invoke_context::InvokeContext;
use solana_program_runtime::solana_rbpf::elf::Executable;
use solana_sdk::pubkey::Pubkey;

use crate::*;

// BPF loader 2
pub static LOADER_KEY: Pubkey = Pubkey::new_from_array([
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x6e, 0x39, 0x5a, 0xe1, 0x28, 0x94, 0x8f, 0xfa, 0x69,
    0x56, 0x93, 0x37, 0x68, 0x18, 0xdd, 0x47, 0x43, 0x52, 0x21, 0xf3, 0xc6, 0x00, 0x00, 0x00, 0x00,
]);

#[derive(PartialEq)]
pub struct LoadedProgram {
    pub rodata: Vec<u8>,
    pub entry_pc: u64,
    pub text_off: i64,
    pub text_sz: u64,
}

impl Debug for LoadedProgram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        writeln!(f, "Rodata size: 0x{:x}", self.rodata.len())?;
        writeln!(f, "Entrypoint: 0x{:x}", self.entry_pc)?;
        writeln!(f, "Text offset: 0x{:x}", self.text_off)?;
        writeln!(f, "Text size: 0x{:x}", self.text_sz)?;
        writeln!(f, "{}", hexdump(&self.rodata))?;
        Ok(())
    }
}

pub fn load_program_firedancer(mut elf: Vec<u8>) -> Result<LoadedProgram, String> {
    unsafe {
        let mut elf_info: fd_sbpf_elf_info_t = std::mem::zeroed();
        if fd_sbpf_elf_peek(&mut elf_info, elf.as_ptr() as *mut c_void, elf.len() as u64).is_null()
        {
            return Err(format!(
                "Firedancer load err: {:?}",
                std::ffi::CStr::from_ptr(fd_sbpf_strerror())
            ));
        }

        let mut rodata = vec![0u8; elf_info.rodata_footprint as usize];
        let syscalls_region = HeapObject::new(
            fd_sbpf_syscalls_align() as usize,
            fd_sbpf_syscalls_footprint() as usize,
        );
        let syscalls: *mut fd_sbpf_syscalls_t =
            fd_sbpf_syscalls_new(syscalls_region.ptr) as *mut fd_sbpf_syscalls_t;
        let syscall_ids: &[u32] = &[
            0xb6fc1a11, 0x686093bb, 0x207559bd, 0x5c2a3178, 0x52ba5096, 0x7ef088ca, 0x9377323c,
            0x48504a38, 0x11f49d86, 0xd7793abb, 0x17e40350, 0x174c5122, 0xaa2607ca, 0xdd1c41a6,
            0xd56b5fe9, 0x23a29a61, 0x3b97b73c, 0xbf7188f6, 0x717cc4a3, 0x434371f8, 0x5fdcde31,
            0x3770fb22, 0xa22b9c85, 0xd7449092, 0x83f00e8f, 0xa226d3eb, 0x5d2245e4, 0x7317b434,
            0xadb8efc8, 0x85532d94,
        ];
        for id in syscall_ids {
            fd_sbpf_syscalls_insert(syscalls, *id);
        }

        let prog_region = HeapObject::new(
            fd_sbpf_program_align() as usize,
            fd_sbpf_program_footprint(&elf_info) as usize,
        );
        let prog = fd_sbpf_program_new(
            prog_region.ptr,
            &elf_info,
            rodata.as_mut_ptr() as *mut c_void,
        );
        let errcode = fd_sbpf_program_load(
            prog,
            elf.as_mut_ptr() as *mut c_void,
            elf.len() as u64,
            syscalls,
        );
        let res = if errcode == 0 {
            Ok(LoadedProgram {
                rodata: std::slice::from_raw_parts(
                    (*prog).rodata as *const u8,
                    (*prog).rodata_sz as usize,
                )
                .to_vec(),
                entry_pc: (*prog).entry_pc,
                text_off: ((*prog).text as *const u8).offset_from((*prog).rodata as *const u8)
                    as i64,
                text_sz: (*prog).text_cnt * 8,
            })
        } else {
            Err(format!(
                "Firedancer load err: {:?}",
                std::ffi::CStr::from_ptr(fd_sbpf_strerror())
            ))
        };
        fd_sbpf_program_delete(prog);
        drop(prog_region);
        fd_sbpf_syscalls_delete(syscalls as *mut c_void);
        drop(syscalls_region);
        res
    }
}

pub fn load_program_labs(elf: &[u8]) -> Result<LoadedProgram, String> {
    let feature_set = solana_sdk::feature_set::FeatureSet::all_enabled();
    let compute_budget = ComputeBudget::default();

    let loader = solana_bpf_loader_program::syscalls::create_program_runtime_environment_v1(
        &feature_set,
        &compute_budget,
        // reject_deployment_of_broken_elfs
        true,
        // debugging_features
        false,
    )
    .map_err(|e| format!("{:?}", e))?;
    let loader = Arc::new(loader);

    let executable: Executable<InvokeContext<'_>> =
        Executable::load(elf, loader).map_err(|e| format!("Labs load err: {:?}", e))?;

    let ro_section = executable.get_ro_section().to_vec();
    let (text_vaddr, text_section) = executable.get_text_bytes();
    Ok(LoadedProgram {
        rodata: ro_section,
        entry_pc: executable.get_entrypoint_instruction_offset() as u64,
        text_off: (text_vaddr - 0x1_0000_0000) as i64,
        text_sz: (text_section.len() as u64) & (!7u64), // not necessarily multiple of 8
    })
}
