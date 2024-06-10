mod error;
mod shutdown;
mod request_handling;

use clap::Parser;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::{SocketAddr};
use std::path::{PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::error::AppError;
use crate::shutdown::setup_shutdown_receiver;
use crate::request_handling::handle_req;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Config {
    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    port: u16,
    #[arg(short = 'd', long = "data-dir")]
    data_dir: PathBuf,
    #[arg(short = 'a', long = "push-authorization")]
    push_authorization: String
}

#[tokio::main]
async fn main()  -> Result<(),AppError>{
    let shared_config = Arc::new(Config::parse());

    let addr = SocketAddr::from(([0, 0, 0, 0], shared_config.port));
    let mut shutdown_rx = setup_shutdown_receiver()?;

    println!("server is waiting for incoming connections on {}", addr);
    let listener = TcpListener::bind(addr).await?;

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                println!("Received shutdown signal, stopping...");
                break;
            }
            Ok((stream, _)) = listener.accept() => {
                let shared_config = shared_config.clone();
                tokio::task::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service_fn(move |req| handle_req(req, shared_config.clone()) )).await {
                        eprintln!("Error serving connection: {:?}", err);
                    }
                });
            }
        }
    }

    Ok(())
}





