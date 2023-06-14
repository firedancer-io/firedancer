use std::path::Path;

use super::*;
use crate::security::*;
use crate::utility::*;

const NAME: &str = "frank";
const CNC_APP_SIZE: u32 = 4032;
const POD_SIZE: u32 = 16384;

pub(super) const STAGE: Stage = Stage {
    name: NAME,
    enabled: None,
    // We can't really verify if a frank workspace has been set up correctly, so if we are
    // running it we just recreate it every time.
    always_recreate: true,
    explain_init_permissions: Some(explain_init_permissions),
    explain_fini_permissions: None,
    init: Some(step),
    fini: None,
    check,
};

#[rustfmt::skip]
fn explain_init_permissions(config: &Config) -> Vec<Option<String>> {
    if config.development.netns.enabled {
        vec![
            check_process_cap(NAME, CAP_SYS_ADMIN, "enter a network namespace"),
        ]
    } else {
        vec![]
    }
}

#[rustfmt::skip]
fn step(config: &mut Config) {
    let bin = &config.binary_dir;
    let name = &config.name;
    let prefix = "firedancer";
    let workspace = format!("{}.wksp", &config.name);
    let interface = &config.tiles.quic.interface;

    if config.development.netns.enabled {
        // Enter network namespace for bind. This is only needed for a check that the interface
        // exists.. we can probably skip that.
        set_network_namespace(&format!("/var/run/netns/{}", interface));
    }

    // Main pod and CNC
    let pod = run!("{bin}/fd_pod_ctl new {workspace} {POD_SIZE}");
    let main_cnc = run!("{bin}/fd_tango_ctl new-cnc {workspace} 0 tic {CNC_APP_SIZE}");
    run!("{bin}/fd_pod_ctl insert {pod} cstr {prefix}.main.cnc {main_cnc}");

    // Pack tiles
    let cnc = run!("{bin}/fd_tango_ctl new-cnc {workspace} 0 tic {CNC_APP_SIZE}");
    let mcache = run!("{bin}/fd_tango_ctl new-mcache {workspace} {} 0 0", config.tiles.pack.max_pending_transactions);
    
    let dcache = run!("{bin}/fd_tango_ctl new-dcache {workspace} 4808 {} 1 1 0", config.tiles.pack.max_pending_transactions);
    let (pack_scratch, cu_est_table) = if Path::new(&format!("{bin}/fd_pack_ctl")).exists() {
        // TODO: Always enable this when merged with pack changes in 1.2
        let pack_scratch = run!("{bin}/fd_pack_ctl new-scratch {workspace} {} {}", config.tiles.pack.solana_labs_bank_thread_count, config.tiles.pack.max_pending_transactions);
        let cu_est_table = run!("{bin}/fd_pack_ctl new-cu-est-tbl {workspace} {} {} {}", config.tiles.pack.compute_unit_estimator_table_size, config.tiles.pack.compute_unit_estimator_ema_history, config.tiles.pack.compute_unit_estimator_ema_default);
        (pack_scratch, cu_est_table)
    } else {
        ("unused".to_string(), "unused".to_string())
    };

    let return_fseq = run!("{bin}/fd_tango_ctl new-fseq {workspace} 0");
    run!("{bin}/fd_pod_ctl \
        insert {pod} cstr {prefix}.pack.cnc {cnc} \
        insert {pod} cstr {prefix}.pack.out-mcache {mcache} \
        insert {pod} cstr {prefix}.pack.out-dcache {dcache} \
        insert {pod} cstr {prefix}.pack.scratch {pack_scratch} \
        insert {pod} cstr {prefix}.pack.cu-est-tbl {cu_est_table} \
        insert {pod} cstr {prefix}.pack.return-fseq {return_fseq} \
        insert {pod} ulong {prefix}.pack.bank-cnt {solana_labs_bank_thread_count} \
        insert {pod} ulong {prefix}.pack.txnq-sz {max_pending_transactions} \
        insert {pod} ulong {prefix}.pack.cu-est-tbl-sz {compute_unit_estimator_table_size} \
        insert {pod} uint {prefix}.pack.cu-limit {solana_labs_bank_thread_compute_units_executed_per_second}",
        solana_labs_bank_thread_count=config.tiles.pack.solana_labs_bank_thread_count,
        max_pending_transactions=config.tiles.pack.max_pending_transactions,
        compute_unit_estimator_table_size=config.tiles.pack.compute_unit_estimator_table_size,
        solana_labs_bank_thread_compute_units_executed_per_second=config.tiles.pack.solana_labs_bank_thread_compute_units_executed_per_second);

    // Dedup tiles
    let cnc = run!("{bin}/fd_tango_ctl new-cnc {workspace} 0 tic {CNC_APP_SIZE}");
    let tcache = run!("{bin}/fd_tango_ctl new-tcache {workspace} {} 0", config.tiles.dedup.signature_cache_size);
    let mcache = run!("{bin}/fd_tango_ctl new-mcache {workspace} {} 0 0", config.tiles.verify.receive_buffer_size); // Same as verify tile depth
    let fseq = run!("{bin}/fd_tango_ctl new-fseq {workspace} 0");
    run!("{bin}/fd_pod_ctl \
        insert {pod} cstr {prefix}.dedup.cnc {cnc} \
        insert {pod} cstr {prefix}.dedup.tcache {tcache} \
        insert {pod} cstr {prefix}.dedup.mcache {mcache} \
        insert {pod} cstr {prefix}.dedup.fseq {fseq}");

    let mut verify_info = vec![];

    // Verify tiles
    for i in 0..config.layout.verify_tile_count {
        let in_mcache = run!("{bin}/fd_tango_ctl new-mcache {workspace} {} 0 0", config.tiles.verify.receive_buffer_size);
        let in_dcache = run!("{bin}/fd_tango_ctl new-dcache {workspace} {mtu} {receive_buffer_size} 1 1 {app_size}",
            mtu=config.tiles.verify.mtu,
            receive_buffer_size=config.tiles.verify.receive_buffer_size,
            app_size=config.tiles.verify.receive_buffer_size * 32);
        let in_fseq = run!("{bin}/fd_tango_ctl new-fseq {workspace} 0");
        run!("{bin}/fd_pod_ctl \
            insert {pod} cstr {prefix}.verifyin.v{i}in.mcache {in_mcache} \
            insert {pod} cstr {prefix}.verifyin.v{i}in.dcache {in_dcache} \
            insert {pod} cstr {prefix}.verifyin.v{i}in.fseq {in_fseq}");

        let cnc = run!("{bin}/fd_tango_ctl new-cnc {workspace} 2 tic {CNC_APP_SIZE}");
        let mcache = run!("{bin}/fd_tango_ctl new-mcache {workspace} {} 0 0", config.tiles.verify.receive_buffer_size);
        let dcache = run!("{bin}/fd_tango_ctl new-dcache {workspace} {mtu} {receive_buffer_size} 1 1 0",
            mtu=config.tiles.verify.mtu,
            receive_buffer_size=config.tiles.verify.receive_buffer_size);
        let fseq = run!("{bin}/fd_tango_ctl new-fseq {workspace} 0");
        run!("{bin}/fd_pod_ctl \
            insert {pod} cstr {prefix}.verify.v{i}.cnc {cnc} \
            insert {pod} cstr {prefix}.verify.v{i}.mcache {mcache} \
            insert {pod} cstr {prefix}.verify.v{i}.dcache {dcache} \
            insert {pod} cstr {prefix}.verify.v{i}.fseq {fseq}");

        verify_info.push((in_mcache, in_dcache, in_fseq));
    }

    // QUIC tiles
    for (i, (verify_mcache, verify_dcache, verify_fseq)) in verify_info.into_iter().enumerate() {
        let cnc = run!("{bin}/fd_tango_ctl new-cnc {workspace} 2 tic {CNC_APP_SIZE}");
        let quic = if Path::new(&format!("{bin}/fd_quic_ctl")).exists() {
            // TODO: Always enable this when merged with QUIC changes in 1.1
            run!("{bin}/fd_quic_ctl new-quic {workspace}")
        } else {
            "unused".to_owned()
        };
        let xsk = run!("{bin}/fd_xdp_ctl new-xsk {workspace} 2048 {} {}", config.tiles.quic.xdp_rx_queue_size, config.tiles.quic.xdp_tx_queue_size);
        run!("{bin}/fd_xdp_ctl bind-xsk {xsk} {name} {interface} {i}");
        let xsk_aio = run!("{bin}/fd_xdp_ctl new-xsk-aio {workspace} {} {}", config.tiles.quic.xdp_tx_queue_size, config.tiles.quic.xdp_aio_depth);

        run!("{bin}/fd_pod_ctl
            insert {pod} cstr {prefix}.quic.quic{i}.cnc {cnc} \
            insert {pod} cstr {prefix}.quic.quic{i}.mcache {mcache} \
            insert {pod} cstr {prefix}.quic.quic{i}.dcache {dcache} \
            insert {pod} cstr {prefix}.quic.quic{i}.fseq {fseq} \
            insert {pod} cstr {prefix}.quic.quic{i}.quic {quic} \
            insert {pod} cstr {prefix}.quic.quic{i}.xsk {xsk} \
            insert {pod} cstr {prefix}.quic.quic{i}.xsk_aio {xsk_aio}",
            mcache=verify_mcache,
            dcache=verify_dcache,
            fseq=verify_fseq);
    }

    let listen_address = super::netns::listen_address(config);
    let src_mac_address = super::netns::src_mac_address(config);

    run!("{bin}/fd_pod_ctl \
        insert {pod} cstr {prefix}.quic_cfg.cert_file {cert_file} \
        insert {pod} cstr {prefix}.quic_cfg.key_file {key_file} \
        insert {pod} cstr {prefix}.quic_cfg.ip_addr {ip_addr} \
        insert {pod} ushort {prefix}.quic_cfg.listen_port {listen_port} \
        insert {pod} cstr {prefix}.quic_cfg.src_mac_addr {src_mac_address} \
        insert {pod} ulong {prefix}.quic_cfg.idle_timeout_ms 1000",
        cert_file=format!("{}/cert.pem", &config.scratch_directory),
        key_file=format!("{}/key.pem", &config.scratch_directory),
        ip_addr=listen_address,
        listen_port=config.tiles.quic.listen_port);

    config.frank.pod = pod.split(':').collect::<Vec<&str>>()[1].parse().unwrap();
    config.frank.main_cnc = main_cnc.split(':').collect::<Vec<&str>>()[1]
            .parse()
            .unwrap();
    config.frank.src_mac_address = src_mac_address;
    config.frank.listen_address = listen_address;

    config.dump_to_bash();
}

fn check(_: &Config) -> CheckResult {
    // Partially configured so the runner tries to perform `undo` every time as well.
    partially_configured!("frank must be reconfigured every launch")
}
