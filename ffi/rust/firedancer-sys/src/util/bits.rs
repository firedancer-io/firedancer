#[inline]
pub unsafe fn fd_ulong_svw_dec_sz(b: *const u8) -> u64 {
    (0x9131512181314121u64 >> ((*(b as *const u64) & 15u64) << 2)) & 15u64
}

#[inline]
pub unsafe fn fd_ulong_svw_dec_fixed(b: *const u8, csz: u64) -> u64 {
    match csz {
        1 => (*b as u64) >> 1,
        2 => ((*(b as *const u16) as u64) >> 3) & 1023,
        3 => ((*(b as *const u16) as u64) >> 3) | (((*(b.offset(2)) as u64) & 0x1f) << 13),
        4 => ((*(b as *const u32) as u64) >> 4) & 16777215,
        5 => ((*(b as *const u32) as u64) >> 4) | (((*(b.offset(4)) as u64) & 0x0f) << 28),
        8 => (*(b as *const u64) >> 4) & 72057594037927935,
        _ => (*(b as *const u64) >> 4) | ((*(b.offset(8)) as u64) << 60),
    }
}
