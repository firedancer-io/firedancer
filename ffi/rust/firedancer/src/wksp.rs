use firedancer_sys::util::fd_wksp_pod_attach;

// TODO higher level binding for pod *const u8 with implicit Drop

pub fn pod_attach(gaddr: &str) -> *const u8 {
    let gaddr_cstr = std::ffi::CString::new(gaddr).unwrap();
    let gaddr_ptr = gaddr_cstr.as_ptr();
    unsafe { fd_wksp_pod_attach(gaddr_ptr) }
}
