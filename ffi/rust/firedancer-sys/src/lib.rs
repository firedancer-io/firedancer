#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

#[allow(dead_code)]
mod generated {
    type schar = i8;
    type uchar = i8;
    type ushort = u16;
    type uint = u32;
    type ulong = u64;

    include!("generated.rs");
}

pub mod util;
