use std::net::ToSocketAddrs;
use std::sync::Arc;
use clap::Parser;
use hyper::Method;
use hyper::{
    server::Server,
    Body,
    Request,
    Response,
};
use prometheus::{
    Encoder,
    TextEncoder,
};
use firedancer::{
    fd_boot,
    fd_halt,
    fd_log_info,
    fd_log_notice,
    fd_log_warning,
};
use firedancer_sys::util::fd_wksp_pod_detach;

mod metrics;
use metrics::*;

// TODO: Switch to fd_env

/// Command-line args
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Listen address (e.g. 127.0.0.1:9595)
    #[arg(long)]
    listen: String,

    #[arg(long)]
    pod: String,

    #[arg(long)]
    cfg: String,
}

/// Requested on a /metrics HTTP request.
/// Reads current Frankendancer state and returns serialized Prometheus metrics.
async fn service_metrics_request(
    spy: Arc<FrankSpy>,
    _req: Request<Body>,
) -> Result<Response<Body>, anyhow::Error> {
    if _req.method() != Method::GET {
        return Ok(Response::builder()
            .status(405)
            .body(Body::from("Method Not Allowed"))?);
    }
    if _req.uri().path() != "/metrics" {
        return Ok(Response::builder()
            .status(404)
            .body(Body::from("Not Found"))?);
    }

    let metric_families = spy.gather();

    let encoder = TextEncoder::new();
    let response_body = encoder.encode_to_string(&metric_families);

    let response_body = match response_body {
        Ok(res) => res,
        Err(err) => {
            fd_log_warning!("Failed to assemble response: {}", err);
            return Ok(Response::builder()
                .status(500)
                .body(Body::from("Internal Server Error"))?);
        }
    };

    Ok(Response::builder()
        .status(if response_body.is_empty() { 204 } else { 200 })
        .header("Content-Type", encoder.format_type())
        .body(Body::from(response_body))
        .expect("Failed to assemble response"))
}

async fn run_server(args: Args, spy: FrankSpy) {
    let spy = Arc::new(spy);
    let service_fn = hyper::service::make_service_fn(move |_conn| {
        let spy = Arc::clone(&spy);
        async move {
            let spy = Arc::clone(&spy);
            Ok::<_, anyhow::Error>(hyper::service::service_fn(move |req| {
                let spy = Arc::clone(&spy);
                service_metrics_request(spy, req)
            }))
        }
    });

    let socket_addr = args
        .listen
        .to_socket_addrs()
        .expect("Invalid listen address")
        .next()
        .expect("No listen address");
    Server::bind(&socket_addr)
        .serve(service_fn)
        .await
        .expect("Server failed");
}

fn main() {
    env_logger::init();

    let args = Args::parse();

    fd_boot(&[
        "--log-app",
        "exporter",
        "--log-level-stderr",
        "0",
        "--log-path",
        "",
    ]);

    fd_log_notice!("Serving Prometheus metrics on {}", args.listen);

    fd_log_info!(
        "using configuration in pod --pod {} at path --cfg {}",
        args.pod,
        args.cfg
    );

    let spy = unsafe {
        let pod = firedancer::wksp::pod_attach(&args.pod);
        let cfg_pod = firedancer::pod::query_subpod(pod, &args.cfg);
        assert!(!cfg_pod.is_null(), "path not found");

        let spy = FrankSpy::new(cfg_pod);
        fd_wksp_pod_detach(pod);
        spy
    };

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run_server(args, spy));

    unsafe {
        fd_halt();
    }
}
