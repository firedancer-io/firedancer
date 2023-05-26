#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::upper_case_acronyms)]

#[allow(dead_code)]
mod generated {
    type schar = i8;
    type uchar = u8;
    type ushort = u16;
    type uint = u32;
    type ulong = u64;

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub mod ballet;
pub mod tango;
pub mod util;
