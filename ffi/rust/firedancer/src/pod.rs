use std::ffi::c_void;
use firedancer_sys::util::{
    fd_pod_info_t,
    fd_pod_query_subpod,
    fd_ulong_svw_dec_fixed,
    fd_ulong_svw_dec_sz,
};

pub struct PodIter {
    cursor: *const u8,
    stop: *const u8,
}

impl PodIter {
    pub unsafe fn new(pod: *const u8) -> Self {
        if pod.is_null() {
            return Self {
                cursor: std::ptr::null(),
                stop: std::ptr::null(),
            };
        }
        let csz = fd_ulong_svw_dec_sz(pod);
        PodIter {
            cursor: pod.offset((csz*3) as isize),
            stop: pod.offset(fd_ulong_svw_dec_fixed(pod, csz) as isize),
        }
    }

    // fd_pod_iter_next
    unsafe fn iter_next(&mut self) {
        // Skip over current key
        let ksz = fd_ulong_svw_dec_sz(self.cursor);
        let key_sz = fd_ulong_svw_dec_fixed(self.cursor, ksz);
        self.cursor = self.cursor.add((ksz + key_sz) as usize);

        // Skip over current type
        self.cursor = self.cursor.add(1);

        // Skip over current val
        let vsz = fd_ulong_svw_dec_sz(self.cursor);
        let val_sz = fd_ulong_svw_dec_fixed(self.cursor, vsz);
        self.cursor = self.cursor.add((vsz + val_sz) as usize);
    }

    // fd_pod_iter_done
    fn iter_done(&self) -> bool {
        self.cursor >= self.stop
    }

    // fd_pod_iter_info
    unsafe fn iter_info(&self) -> fd_pod_info_t {
        let mut cursor = self.cursor;

        // Unpack key
        let ksz = fd_ulong_svw_dec_sz(cursor);
        let key_sz = fd_ulong_svw_dec_fixed(cursor, ksz);
        cursor = cursor.add(ksz as usize);
        let key = cursor as *const i8;
        cursor = cursor.add(key_sz as usize);

        // Unpack type
        let val_type = (*cursor) as i32;
        cursor = cursor.add(1);

        // Unpack val
        let vsz = fd_ulong_svw_dec_sz(cursor);
        let val_sz = fd_ulong_svw_dec_fixed(cursor, vsz);
        cursor = cursor.add(vsz as usize);
        let val = cursor as *const c_void;
        //cursor = cursor.add(val_sz as usize);

        fd_pod_info_t {
            key,
            key_sz,
            val_type,
            val,
            val_sz,
            parent: std::ptr::null_mut(),
        }
    }
}

impl Iterator for PodIter {
    type Item = fd_pod_info_t;

    fn next(&mut self) -> Option<Self::Item> {
        if self.iter_done() {
            return None;
        }
        let info = unsafe { self.iter_info() };
        unsafe {
            self.iter_next();
        }
        Some(info)
    }
}

pub unsafe fn query_subpod(pod: *const u8, key: &str) -> *const u8 {
    let key_cstr = std::ffi::CString::new(key).unwrap();
    let key_ptr = key_cstr.as_ptr();
    fd_pod_query_subpod(pod, key_ptr)
}
