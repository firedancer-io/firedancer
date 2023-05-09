use firedancer_sys::ballet::*;
use std::ffi::c_void;
use std::fmt::Debug;
use solana_program_runtime::compute_budget::ComputeBudget;
use solana_sdk::pubkey::Pubkey;

/* BPF loader 2 */
static LOADER_KEY: Pubkey = Pubkey::new_from_array([
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x6e, 0x39, 0x5a, 0xe1, 0x28, 0x94, 0x8f, 0xfa, 0x69,
    0x56, 0x93, 0x37, 0x68, 0x18, 0xdd, 0x47, 0x43, 0x52, 0x21, 0xf3, 0xc6, 0x00, 0x00, 0x00, 0x00,
]);

struct LoadedProgram {
    rodata: Vec<u8>,
    entry_pc: u64,
    text_off: i64,
    text_sz: u64,
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

fn load_program_firedancer(mut elf: Vec<u8>) -> Option<LoadedProgram> {
    unsafe {
        let syscalls_layout = std::alloc::Layout::from_size_align_unchecked(
            fd_sbpf_syscalls_footprint(),
            fd_sbpf_syscalls_align(),
        );
        let syscalls = fd_sbpf_syscalls_new(std::alloc::alloc(syscalls_layout) as *mut c_void);
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

        let prog_layout = std::alloc::Layout::from_size_align_unchecked(
            fd_sbpf_program_footprint() as usize,
            fd_sbpf_program_align() as usize,
        );
        let prog = fd_sbpf_program_new(std::alloc::alloc(prog_layout) as *mut c_void);
        let errcode = fd_sbpf_program_load(
            prog,
            elf.as_mut_ptr() as *mut c_void,
            elf.len() as u64,
            syscalls,
        );
        let res = if errcode == 0 {
            let info = fd_sbpf_program_get_info(prog);
            Some(LoadedProgram {
                rodata: std::slice::from_raw_parts(
                    (*info).rodata as *const u8,
                    (*info).rodata_sz as usize,
                )
                .to_vec(),
                entry_pc: (*info).entry_pc,
                text_off: ((*info).text as *const i8).offset_from((*info).rodata) as i64,
                text_sz: (*info).text_cnt * 8,
            })
        } else {
            eprintln!(
                "Firedancer load err: {:?}",
                std::ffi::CStr::from_ptr(fd_sbpf_strerror())
            );
            None
        };
        std::alloc::dealloc(fd_sbpf_program_delete(prog) as *mut u8, prog_layout);
        std::alloc::dealloc(
            fd_sbpf_syscalls_delete(syscalls) as *mut u8,
            syscalls_layout,
        );
        res
    }
}

fn load_program_labs(elf: Vec<u8>) -> Option<LoadedProgram> {
    let feature_set = solana_sdk::feature_set::FeatureSet::all_enabled();
    let mut load_program_metrics =
        solana_program_runtime::loaded_programs::LoadProgramMetrics::default();
    let compute_budget = ComputeBudget::default();
    let result = solana_bpf_loader_program::load_program_from_bytes(
        &feature_set,
        &compute_budget,
        /* log_collector */ None,
        &mut load_program_metrics,
        &elf,
        &LOADER_KEY,
        /* account_size */ elf.len(),
        /* slot */ 1,
        /* reject_deployment_of_broken_elfs */ true,
        /* debugging_features */ false,
    )
    .ok()?;
    let program = match result.program {
        solana_program_runtime::loaded_programs::LoadedProgramType::LegacyV0(e) => e,
        solana_program_runtime::loaded_programs::LoadedProgramType::LegacyV1(e) => e,
        _ => return None,
    };
    let executable = program.get_executable();
    let ro_section = executable.get_ro_section().to_vec();
    let (text_vaddr, text_section) = executable.get_text_bytes();
    Some(LoadedProgram {
        rodata: ro_section,
        entry_pc: executable.get_entrypoint_instruction_offset() as u64,
        text_off: (text_vaddr - 0x1_0000_0000) as i64,
        text_sz: text_section.len() as u64,
    })
}

fn main() {
    let elf_bytes = std::fs::read(std::env::args().nth(1).expect("Usage: sbpf-diff <prog>"))
        .expect("read failed");

    let prog_sl = format!("{:?}", load_program_labs(elf_bytes.clone()).expect("Labs failed to load"));
    let prog_fd = format!("{:?}", load_program_firedancer(elf_bytes).expect("Firedancer failed to load"));

    let mut matches = true;
    for diff in diff::lines(&prog_sl, &prog_fd) {
        let prev_matches = matches;
        matches = false;
        match diff {
            diff::Result::Left(l) => println!("SL {}", l),
            diff::Result::Both(_, _) => matches = true,
            diff::Result::Right(r) => println!("FD {}", r),
        }
        if !prev_matches && matches {
            println!("...");
        }
    }
}

fn hexdump(bytes: &[u8]) -> String {
    let mut buffer = Vec::<u8>::new();
    hxdmp::hexdump(bytes, &mut buffer).unwrap();
    String::from_utf8_lossy(&buffer).to_string()
}
