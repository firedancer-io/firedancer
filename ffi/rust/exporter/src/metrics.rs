use cstr::cstr;
use std::ffi::CStr;
use firedancer::pod::PodIter;
use firedancer_sys::tango::fd_cnc_t;
use firedancer_sys::disco::quic::{
    FD_QUIC_CNC_DIAG_CHUNK_IDX,
    FD_QUIC_CNC_DIAG_TPU_PUB_CNT,
    FD_QUIC_CNC_DIAG_TPU_PUB_SZ,
};
use firedancer_sys::tango::{
    fd_cnc_app_laddr_const,
    fd_cnc_app_sz,
    fd_cnc_join,
    fd_cnc_leave,
};
use firedancer_sys::util::{
    fd_pod_cnt_subpod,
    fd_pod_query_subpod,
    fd_wksp_pod_map,
    fd_wksp_pod_unmap,
    FD_POD_VAL_TYPE_SUBPOD,
};
use firedancer::fd_log_info;
use prometheus::proto::{
    Counter,
    Gauge,
    LabelPair,
    Metric,
    MetricFamily,
    MetricType,
};

macro_rules! label_pairs {
    ($($k:expr => $v:expr),*) => {
        {
            vec![
                $( new_label_pair($k, $v), )*
            ]
        }
    };
}

/// Handles to various Frankendancer objects to extract monitoring data from.
pub(crate) struct FrankSpy {
    main_cnc: *mut fd_cnc_t,
    pack_cnc: *mut fd_cnc_t,
    verify: Vec<FrankVerifySpy>,
    quic: Vec<FrankQuicSpy>,
}

impl FrankSpy {
    pub(crate) unsafe fn new(cfg_pod: *const u8) -> Self {
        let quic_pods = fd_pod_query_subpod(cfg_pod, cstr!("quic").as_ptr());
        let quic_cnt = fd_pod_cnt_subpod(quic_pods);
        fd_log_info!("{} quic found", quic_cnt);

        let verify_pods = fd_pod_query_subpod(cfg_pod, cstr!("verify").as_ptr());
        let verify_cnt = fd_pod_cnt_subpod(verify_pods);
        fd_log_info!("{} verify found", verify_cnt);

        let main_cnc = fd_cnc_join(fd_wksp_pod_map(cfg_pod, cstr!("main.cnc").as_ptr()));
        fd_log_info!("joining main.cnc");
        assert!(!main_cnc.is_null());
        assert!(fd_cnc_app_sz(main_cnc) >= 64);

        let pack_cnc = fd_cnc_join(fd_wksp_pod_map(cfg_pod, cstr!("pack.cnc").as_ptr()));
        fd_log_info!("joining pack.cnc");
        assert!(!pack_cnc.is_null());
        assert!(fd_cnc_app_sz(pack_cnc) >= 64);

        let quic = PodIter::new(quic_pods)
            .filter(|info| info.val_type == FD_POD_VAL_TYPE_SUBPOD as i32)
            .map(|info| {
                let quic_name = unsafe { CStr::from_ptr(info.key) };
                let quic_pod = info.val as *const u8;

                fd_log_info!("joining quic.{}.cnc", quic_name.to_str().unwrap());
                let quic_cnc = fd_cnc_join(fd_wksp_pod_map(quic_pod, cstr!("cnc").as_ptr()));

                FrankQuicSpy {
                    name: quic_name.to_str().unwrap().to_string(),
                    cnc: quic_cnc,
                }
            })
            .collect::<Vec<_>>();

        let verify = PodIter::new(verify_pods)
            .filter(|info| info.val_type == FD_POD_VAL_TYPE_SUBPOD as i32)
            .map(|info| {
                let verify_name = unsafe { CStr::from_ptr(info.key) };
                let verify_pod = info.val as *const u8;

                fd_log_info!("joining verify.{}.cnc", verify_name.to_str().unwrap());
                let verify_cnc = fd_cnc_join(fd_wksp_pod_map(verify_pod, cstr!("cnc").as_ptr()));

                FrankVerifySpy {
                    name: verify_name.to_str().unwrap().to_string(),
                    cnc: verify_cnc,
                }
            })
            .collect::<Vec<_>>();

        FrankSpy {
            main_cnc,
            pack_cnc,
            quic,
            verify,
        }
    }

    pub(crate) fn gather(&self) -> Vec<MetricFamily> {
        let mut mf = Vec::new();
        self.gather_quic(&mut mf);
        mf
    }

    fn gather_quic(&self, mf: &mut Vec<MetricFamily>) {
        if self.quic.is_empty() {
            return;
        }
        let mut quic_chunk_idx_vec = Vec::<Metric>::with_capacity(self.quic.len());
        let mut quic_tpu_pub_cnt_vec = Vec::<Metric>::with_capacity(self.quic.len());
        let mut quic_tpu_pub_sz_vec = Vec::<Metric>::with_capacity(self.quic.len());

        for quic in &self.quic {
            let cnc_diag = unsafe { fd_cnc_app_laddr_const(quic.cnc) } as *const u64;

            let quic_chunk_idx = unsafe { *(cnc_diag.add(FD_QUIC_CNC_DIAG_CHUNK_IDX as usize)) };
            let quic_tpu_pub_cnt =
                unsafe { *(cnc_diag.add(FD_QUIC_CNC_DIAG_TPU_PUB_CNT as usize)) };
            let quic_tpu_pub_sz = unsafe { *(cnc_diag.add(FD_QUIC_CNC_DIAG_TPU_PUB_SZ as usize)) };

            let mut m = quic.new_metric();
            m.set_gauge(new_gauge(quic_chunk_idx as f64));
            quic_chunk_idx_vec.push(m);

            let mut m = quic.new_metric();
            m.set_counter(new_counter(quic_tpu_pub_cnt as f64));
            quic_tpu_pub_cnt_vec.push(m);

            let mut m = quic.new_metric();
            m.set_counter(new_counter(quic_tpu_pub_sz as f64));
            quic_tpu_pub_sz_vec.push(m);
        }

        let mut quic_chunk_idx = MetricFamily::new();
        quic_chunk_idx.set_name("firedancer_quic_chunk_idx".to_string());
        quic_chunk_idx.set_help("publish dcache chunk index of QUIC tile".to_string());
        quic_chunk_idx.set_field_type(MetricType::GAUGE);
        quic_chunk_idx.set_metric(quic_chunk_idx_vec.into());
        mf.push(quic_chunk_idx);

        let mut quic_tpu_pub_cnt = MetricFamily::new();
        quic_tpu_pub_cnt.set_name("firedancer_quic_tpu_publish_txns_total".to_string());
        quic_tpu_pub_cnt.set_help("Number of TPU txns published by QUIC tile".to_string());
        quic_tpu_pub_cnt.set_field_type(MetricType::COUNTER);
        quic_tpu_pub_cnt.set_metric(quic_tpu_pub_cnt_vec.into());
        mf.push(quic_tpu_pub_cnt);

        let mut quic_tpu_pub_sz = MetricFamily::new();
        quic_tpu_pub_sz.set_name("firedancer_quic_tpu_publish_bytes_total".to_string());
        quic_tpu_pub_sz
            .set_help("Cumulative byte size of TPU txns published by QUIC tile".to_string());
        quic_tpu_pub_sz.set_field_type(MetricType::COUNTER);
        quic_tpu_pub_sz.set_metric(quic_tpu_pub_sz_vec.into());
        mf.push(quic_tpu_pub_sz);
    }
}

// TODO: hacky
unsafe impl Send for FrankSpy {}

// TODO: hacky
unsafe impl Sync for FrankSpy {}

impl Drop for FrankSpy {
    fn drop(&mut self) {
        unsafe {
            fd_wksp_pod_unmap(fd_cnc_leave(self.main_cnc));
            fd_wksp_pod_unmap(fd_cnc_leave(self.pack_cnc));
            for quic in &self.quic {
                fd_wksp_pod_unmap(fd_cnc_leave(quic.cnc));
            }
            for verify in &self.verify {
                fd_wksp_pod_unmap(fd_cnc_leave(verify.cnc));
            }
        }
    }
}

pub(crate) struct FrankVerifySpy {
    name: String,
    cnc: *mut fd_cnc_t,
}

pub(crate) struct FrankQuicSpy {
    name: String,
    cnc: *mut fd_cnc_t,
}

impl FrankQuicSpy {
    fn new_metric(&self) -> Metric {
        let mut m = Metric::new();
        m.set_label(label_pairs!("tile" => &self.name).into());
        m
    }
}

fn new_gauge(f: f64) -> Gauge {
    let mut g = Gauge::new();
    g.set_value(f);
    g
}

fn new_counter(f: f64) -> Counter {
    let mut c = Counter::new();
    c.set_value(f);
    c
}

fn new_label_pair(k: &str, v: &str) -> LabelPair {
    let mut lp = LabelPair::new();
    lp.set_name(k.to_string());
    lp.set_value(v.to_string());
    lp
}
