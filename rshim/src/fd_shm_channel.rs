use {
    crate::fd_ffi::{FD_SHIM_MSG_SZ, FD_SHIM_PAYLOAD_SZ},
    libc::{off_t, size_t},
    nix::{
        fcntl::OFlag,
        sys::{
            mman::{mmap, munmap, shm_open, shm_unlink, MapFlags, ProtFlags},
            stat::Mode,
        },
        unistd::ftruncate,
    },
    std::{
        ffi::c_void,
        hint::spin_loop,
        mem,
        num::NonZeroUsize,
        os::unix::io::{AsRawFd, FromRawFd, OwnedFd},
        path::PathBuf,
        ptr::copy_nonoverlapping,
        sync::atomic::{compiler_fence, AtomicU64, Ordering},
    },
};

pub struct ShmChannelHandle {
    pub ctl_fd: OwnedFd,
    pub msg_fd: OwnedFd,
}

impl ShmChannelHandle {
    pub fn create(name: &str) -> nix::Result<Self> {
        let ctl_name = PathBuf::from(format!("{}.fctl", name));
        let msg_name = PathBuf::from(format!("{}.fmsg", name));

        let ctl_fd = shm_open(
            &ctl_name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_TRUNC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?;
        let msg_fd = shm_open(
            &msg_name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_TRUNC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?;

        shm_unlink(&ctl_name)?;
        shm_unlink(&msg_name)?;

        ftruncate(ctl_fd, mem::size_of::<u64>() as off_t)?;
        ftruncate(msg_fd, FD_SHIM_MSG_SZ as off_t)?;

        let ctl_fd = unsafe { OwnedFd::from_raw_fd(ctl_fd) };
        let msg_fd = unsafe { OwnedFd::from_raw_fd(msg_fd) };

        Ok(Self { ctl_fd, msg_fd })
    }

    pub fn open(self) -> nix::Result<ShmChannel> {
        let shm_ctl = unsafe {
            mmap(
                None,
                NonZeroUsize::new_unchecked(mem::size_of::<u64>() as usize),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                self.ctl_fd.as_raw_fd(),
                0,
            )? as *mut AtomicU64
        };
        let shm_msg = unsafe {
            mmap(
                None,
                NonZeroUsize::new_unchecked(FD_SHIM_MSG_SZ as usize),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                self.msg_fd.as_raw_fd(),
                0,
            )?
        };

        Ok(ShmChannel {
            _handle: self,
            shm_ctl,
            shm_msg,
            rseq: 0u64,
            wseq: 0u64,
        })
    }

    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            ctl_fd: self.ctl_fd.try_clone()?,
            msg_fd: self.msg_fd.try_clone()?,
        })
    }
}

pub struct ShmChannel {
    _handle: ShmChannelHandle,
    shm_ctl: *mut AtomicU64,
    shm_msg: *mut c_void,
    rseq: u64,
    wseq: u64,
}

impl Drop for ShmChannel {
    fn drop(&mut self) {
        unsafe {
            _ = munmap(self.shm_ctl as *mut c_void, mem::size_of::<u64>() as size_t);
            _ = munmap(self.shm_msg, FD_SHIM_MSG_SZ as size_t);
        }
    }
}

impl ShmChannel {
    pub unsafe fn try_recvmsg(&mut self, out: &mut [u8; FD_SHIM_MSG_SZ as usize]) -> Option<usize> {
        const POLL_ATTEMPTS: usize = 1_000_000usize;

        // Poll sequence number for change
        let rseq = self.rseq;
        let cseq_ptr = self.shm_msg as *mut AtomicU64;
        let mut cseq_res = None;
        for _ in 0..POLL_ATTEMPTS {
            let cseq = (*cseq_ptr).load(Ordering::Relaxed);
            if cseq > rseq {
                cseq_res = Some(cseq);
                break;
            }
            spin_loop();
        }

        // Bail if no new sequence number observed
        let cseq = match cseq_res {
            None => return None,
            Some(cseq) => cseq,
        };

        // Peek commit sequence number
        // If mismatch, might indicate a torn write
        let nseq = *(self.shm_msg.offset(FD_SHIM_MSG_SZ as isize - 8) as *mut u64);
        if cseq.wrapping_add(1) != nseq {
            return None;
        }

        // Get payload size
        // Data race might corrupt this field, but this is fine, as it stays bounded
        let payload_sz = *(self.shm_msg.offset(8) as *mut u64);
        if payload_sz > FD_SHIM_PAYLOAD_SZ as u64 {
            return None;
        }

        // Speculatively copy payload into out buffer
        copy_nonoverlapping(
            self.shm_msg.offset(16) as *mut u8,
            out.as_mut_ptr(),
            payload_sz as usize,
        );

        // Check if commit sequence number still matches
        compiler_fence(Ordering::Acquire);
        if nseq != *(self.shm_msg.offset(FD_SHIM_MSG_SZ as isize - 8) as *mut u64) {
            return None;
        }

        // Write ack
        self.rseq = cseq;
        (*(self.shm_ctl)).store(cseq, Ordering::Relaxed);

        Some(payload_sz as usize)
    }

    pub unsafe fn try_sendmsg(&mut self, payload: &[u8]) -> bool {
        const POLL_ATTEMPTS: usize = 1_000_000usize;

        // Wait for reader to catch up
        let last_wseq = self.wseq;
        let mut attempts = 0;
        loop {
            if attempts > POLL_ATTEMPTS {
                return false;
            }
            let last_rseq = (*(self.shm_ctl)).load(Ordering::Relaxed);
            if last_rseq >= last_wseq {
                break;
            }
            spin_loop();
            attempts += 1;
        }

        let wseq = last_wseq.wrapping_add(1);
        self.wseq = wseq;

        // Write new sequence number
        *(self.shm_msg.offset(0) as *mut u64) = wseq;

        // Write new payload size
        let mut payload_sz = payload.len();
        if payload_sz > FD_SHIM_PAYLOAD_SZ as usize {
            payload_sz = FD_SHIM_PAYLOAD_SZ as usize;
        }
        *(self.shm_msg.offset(8) as *mut u64) = payload_sz as u64;

        // Copy new payload into buffer
        copy_nonoverlapping(
            payload.as_ptr(),
            self.shm_msg.offset(16) as *mut u8,
            payload_sz as usize,
        );

        // Commit message
        compiler_fence(Ordering::Release);
        (*(self.shm_msg.offset(FD_SHIM_MSG_SZ as isize - 8) as *mut AtomicU64))
            .store(wseq.wrapping_add(1), Ordering::Relaxed);

        true
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        itertools::Itertools,
        log::*,
        std::{
            io::{stdout, Write},
            thread::sleep,
            time::{self, Duration},
        },
    };

    #[test]
    fn test_shm_channel_write() {
        let channel_id: String = "SHM_CHANNEL_4321".to_string();
        let shm_channel_tx = ShmChannel::new(channel_id);
        let pause_period = time::Duration::from_millis(500);

        //
        // Tx with gap 'pause_period' sent with write_struct_msg() received with get_payload_struct_msg()
        //
        for i in 0..16 {
            info!(
                "shm::tests::test_shm_channel_write   {:?}-th write loop",
                i + 1
            );

            let msg = (0..32).map(|x| (i + 1 + x) as u8).collect_vec();
            let mut msg_ary: [u8; 32] = [0u8; 32];
            msg_ary.copy_from_slice(&msg[..32]);

            let seq = shm_channel_tx.write_struct_msg::<[u8; 32]>(&msg_ary);
            assert_ne!(seq, 0u64);
            info!(
                "shm::tests::test_shm_channel_write   Write   seq={}   msg={:?}",
                seq, &msg_ary
            );
            stdout().flush().unwrap();

            sleep(pause_period);
        }

        //
        // Tx without gap sent with write_struct_msg() received with get_payload_struct_msg()
        //
        for i in 0..16 {
            info!(
                "shm::tests::test_shm_channel_write   {:?}-th write loop   no sleep",
                i + 1
            );

            let msg = (0..32).map(|x| (i + 1 + x) as u8).collect_vec();
            let mut msg_ary: [u8; 32] = [0u8; 32];
            msg_ary.copy_from_slice(&msg[..32]); // (&msg[..32]).clone();

            let seq = shm_channel_tx.write_struct_msg::<[u8; 32]>(&msg_ary);
            assert_ne!(seq, 0u64);
            info!(
                "shm::tests::test_shm_channel_write   Write   seq={}   msg={:?}",
                seq, &msg_ary
            );
            stdout().flush().unwrap();
        }

        //
        // Tx with gap 'pause_period' sent with write_u8arr_msg() received with get_payload_u8arr_msg()
        //
        for i in 0..16 {
            info!(
                "shm::tests::test_shm_channel_write   {:?}-th write loop",
                i + 1
            );

            let msg = (0..32).map(|x| (i + 1 + x) as u8).collect_vec();
            let mut msg_ary: [u8; 32] = [0u8; 32];
            msg_ary.copy_from_slice(&msg[..32]); // (&msg[..32]).clone();

            let seq = shm_channel_tx.write_u8arr_msg(&msg_ary[..(i + 1)]);
            assert_ne!(seq, 0u64);
            info!(
                "shm::tests::test_shm_channel_write   Write   seq={}   msg={:?}",
                seq, &msg_ary
            );
            stdout().flush().unwrap();
            sleep(Duration::from_millis(500));
        }

        //
        // Tx without gap sent with write_u8arr_msg() received with get_payload_u8arr_msg()
        //
        for i in 0..16 {
            info!(
                "shm::tests::test_shm_channel_write   {:?}-th write loop   no sleep",
                i + 1
            );

            let msg = (0..32).map(|x| (i + 1 + x) as u8).collect_vec();
            let mut msg_ary: [u8; 32] = [0u8; 32];
            msg_ary.copy_from_slice(&msg[..32]); // (&msg[..32]).clone();

            let seq = shm_channel_tx.write_u8arr_msg(&msg_ary[..(i + 1)]);
            assert_ne!(seq, 0u64);
            info!(
                "shm::tests::test_shm_channel_write   Write   seq={}   msg={:?}",
                seq, &msg_ary
            );
            stdout().flush().unwrap();
        }

        stdout().flush().unwrap();
    }

    #[test]
    fn test_shm_channel_read() {
        info!("Running shm::tests::test_shm_channel_read");

        let channel_id: String = "SHM_CHANNEL_4321".to_string();
        let channel_bufsz = 8u64;
        let shm_channel_rx = ShmChannelRx::new(channel_id, channel_bufsz);
        info!("shm::tests::test_shm_channel_read   obtained an instance of ShmChannelRx");

        //
        // Rx the Tx with gap 'pause_period' sent with write_struct_msg() received with get_payload_struct_msg()
        //
        for i in 0..16 {
            info!(
                "shm::tests::test_shm_channel_read   {:?}-th read loop",
                i + 1
            );

            let shmmsg = shm_channel_rx.read_shmchannelmsg();
            info!(
                "shm::tests::test_shm_channel_read   Read   (cseq,nseq)={:?}   msg={:?}",
                shmmsg.get_seq(),
                shmmsg.get_payload_struct_msg::<[u8; 32]>()
            );
            stdout().flush().unwrap();
        }

        //
        // Rx the Tx without gap sent with write_struct_msg() received with get_payload_struct_msg()
        //
        for i in 0..16 {
            info!(
                "shm::tests::test_shm_channel_read   {:?}-th read loop   no sleep",
                i + 1
            );

            let shmmsg = shm_channel_rx.read_shmchannelmsg();
            info!(
                "shm::tests::test_shm_channel_read   Read   (cseq,nseq)={:?}   msg={:?}",
                shmmsg.get_seq(),
                shmmsg.get_payload_struct_msg::<[u8; 32]>()
            );
            stdout().flush().unwrap();
        }

        //
        // Rx the Tx with gap 'pause_period' sent with write_u8arr_msg() received with get_payload_u8arr_msg()
        //
        for i in 0..16 {
            info!(
                "shm::tests::test_shm_channel_read   {:?}-th read loop",
                i + 1
            );

            let shmmsg = shm_channel_rx.read_shmchannelmsg();
            info!(
                "shm::tests::test_shm_channel_read   Read   (cseq,nseq)={:?}   msg={:?}",
                shmmsg.get_seq(),
                shmmsg.get_payload_u8arr_msg()
            );
            stdout().flush().unwrap();
        }

        //
        // Rx the Tx without gap sent with write_u8arr_msg() received with get_payload_u8arr_msg()
        //
        for i in 0..16 {
            info!(
                "shm::tests::test_shm_channel_read   {:?}-th read loop   no sleep",
                i + 1
            );

            let shmmsg = shm_channel_rx.read_shmchannelmsg();
            info!(
                "shm::tests::test_shm_channel_read   Read   (cseq,nseq)={:?}   msg={:?}",
                shmmsg.get_seq(),
                shmmsg.get_payload_u8arr_msg()
            );
            stdout().flush().unwrap();
        }

        stdout().flush().unwrap();
    }
}
