use std::alloc::Layout;
use std::ffi::c_void;

pub mod loader;
pub use loader::*;

pub struct HeapObject {
    layout: Layout,
    ptr: *mut c_void,
}

impl HeapObject {
    pub fn new(align: usize, footprint: usize) -> Self {
        let layout = Layout::from_size_align(footprint, align).expect("invalid layout");
        let ptr = unsafe { std::alloc::alloc(layout) as *mut c_void };
        Self { layout, ptr }
    }
}

impl Drop for HeapObject {
    fn drop(&mut self) {
        unsafe {
            std::alloc::dealloc(self.ptr as *mut u8, self.layout);
        }
    }
}

fn hexdump(buffer: &[u8]) -> String {
    // Hexdump routine imported from https://github.com/rustyhorde/hxdmp/
    // ca May 2023.  MIT License.
    // Copyright (c) 2016 The Rust Project Developers, Jason Ozias

    let mut out = String::new();
    let sixteen_iter = buffer.chunks(16).enumerate();
    for (line, parts) in sixteen_iter {
        if line > 0 {
            out += "\n";
        }
        out += &format!("{:04x}: ", line * 16);
        for b in parts {
            out += &format!("{:02X} ", b);
        }
        for _ in parts.len()..16 {
            out += "   ";
        }
        out += " ";
        for b in parts {
            let ch = *b as char;
            if ch.is_ascii_graphic() {
                out += &format!("{}", ch);
            } else {
                out += ".";
            }
        }
    }
    out
}
