use crate::generated::{fd_reedsol_encode_32_32, fd_reedsol_encode_16, fd_reedsol_encode_32, fd_reedsol_encode_64, fd_reedsol_encode_128};
use std::alloc::{alloc, dealloc, handle_alloc_error, Layout};

#[inline(always)]
pub unsafe fn fd_reedsol_encode(
    shred_sz: u64,
    data_shred: *const *const u8,
    data_shred_cnt: u64,
    parity_shred: *const *mut u8,
    parity_shred_cnt: u64,
) {
    if data_shred_cnt == 32 && parity_shred_cnt == 32 {
        let layout = Layout::from_size_align(1024usize, 32usize).unwrap();
        let ptr = alloc(layout);
        if ptr.is_null() {
            handle_alloc_error(layout);
        }
        fd_reedsol_encode_32_32(shred_sz, data_shred, parity_shred, ptr);
        dealloc(ptr, layout);
    } else if data_shred_cnt <= 16 {
        fd_reedsol_encode_16(shred_sz, data_shred, data_shred_cnt, parity_shred, parity_shred_cnt)
    } else if data_shred_cnt <= 32 {
        fd_reedsol_encode_32(shred_sz, data_shred, data_shred_cnt, parity_shred, parity_shred_cnt)
    } else if data_shred_cnt <= 64 {
        fd_reedsol_encode_64(shred_sz, data_shred, data_shred_cnt, parity_shred, parity_shred_cnt)
    } else {
        fd_reedsol_encode_128(shred_sz, data_shred, data_shred_cnt, parity_shred, parity_shred_cnt)
    }
}
