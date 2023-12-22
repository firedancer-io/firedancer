use solana_program_runtime::compute_budget::ComputeBudget;
use solana_program_runtime::invoke_context::InvokeContext;
use solana_program_runtime::solana_rbpf::elf::Executable;

use std::sync::Arc;
use std::mem;

use std::fmt::Debug;

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
        Ok(())
    }
}


#[no_mangle]
pub extern "C" fn industry_init() {
    println!("init rust")
}

#[no_mangle]
extern "C" fn industry_test_one(
    out_result_sz: *mut usize,
    out_result_buf: *mut u8,
    result_buf_sz: usize,
    data: *const u8,
    data_sz: usize,
) -> i32 {

    // The layout of result (out_result_buf) is:
    // - i32: 0 if unpack succeded, -1 if failed
    // - u64: len of rodata:
    // - uchar[]: rodata
    // - u64: entry_pc
    // - i64: text_off
    // - u64: text_sz


    let elf = unsafe {
        if data.is_null() { 
            let buffer = std::slice::from_raw_parts_mut(out_result_buf, result_buf_sz);
            buffer[..mem::size_of::<i32>()].copy_from_slice(&(-1 as i32).to_ne_bytes());
            *out_result_sz = mem::size_of::<i32>();
            return 0 
        }
    
        std::slice::from_raw_parts(data, data_sz)
    };

    let mres = load_program_labs(elf);

    if let Err(_e) = mres {
        unsafe {
            let buffer = std::slice::from_raw_parts_mut(out_result_buf, result_buf_sz);
            buffer[..mem::size_of::<i32>()].copy_from_slice(&(-1 as i32).to_ne_bytes());
            *out_result_sz = mem::size_of::<i32>();
            return 0
        }
    }

    let res = mres.unwrap();
    unsafe {
        *out_result_sz = 0;
        let mut last_sz;

        let mut buffer = std::slice::from_raw_parts_mut(out_result_buf, result_buf_sz);

        // - i32: 0 if unpack succeded, -1 if failed
        last_sz = mem::size_of::<i32>();
        buffer[..last_sz].copy_from_slice(&(0 as i32).to_ne_bytes());
        buffer = &mut buffer[last_sz..];
        *out_result_sz += last_sz;

        // - u64: len of rodata
        last_sz = mem::size_of::<u64>();
        buffer[..last_sz].copy_from_slice(&(res.rodata.len()).to_ne_bytes());
        buffer = &mut buffer[last_sz..];
        *out_result_sz += last_sz;

        // - uchar[]: rodata
        last_sz = res.rodata.len();
        buffer[..last_sz].copy_from_slice(&res.rodata);
        buffer = &mut buffer[last_sz..];
        *out_result_sz += last_sz;

        // - u64: entry_pc
        last_sz = mem::size_of::<u64>();
        buffer[..last_sz].copy_from_slice(&(res.entry_pc).to_ne_bytes());
        buffer = &mut buffer[last_sz..];
        *out_result_sz += last_sz;

        // - i64: text_off
        last_sz = mem::size_of::<i64>();
        buffer[..last_sz].copy_from_slice(&(res.text_off).to_ne_bytes());
        buffer = &mut buffer[last_sz..];
        *out_result_sz += last_sz;

        // - u64: text_sz
        last_sz = mem::size_of::<u64>();
        buffer[..last_sz].copy_from_slice(&(res.text_sz).to_ne_bytes());
        // buffer = &mut buffer[last_sz..];
        *out_result_sz += last_sz;

        0
    }
}


fn load_program_labs(elf: &[u8]) -> Result<LoadedProgram, String> {
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
