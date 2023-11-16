#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::upper_case_acronyms)]

type schar = i8;
type uchar = u8;
type ushort = u16;
type uint = u32;
type ulong = u64;

#[allow(dead_code)]
mod genutil {
    use crate::{schar, uchar, ushort, uint, ulong};
    include!(concat!(env!("OUT_DIR"), "/bindings_util.rs"));
}

#[allow(dead_code)]
mod genballet {
    use crate::{uchar, ushort, uint, ulong};
    use crate::genutil::fd_rng_t;
    include!(concat!(env!("OUT_DIR"), "/bindings_ballet.rs"));
}

#[allow(dead_code)]
mod gentango {
    use crate::{uchar, ushort, uint, ulong};
    use crate::genutil::fd_rng_t;
    include!(concat!(env!("OUT_DIR"), "/bindings_tango.rs"));
}

pub mod ballet;
pub mod tango;
pub mod util;
