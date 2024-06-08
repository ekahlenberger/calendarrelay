mod error;
mod shutdown;

use std::net::SocketAddr;
use clap::Parser;

use crate::error::AppError;
use crate::shutdown::setup_shutdown_receiver;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Config {
    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    port: u16,
}



#[tokio::main]
async fn main()  -> Result<(),AppError>{
    let config = Config::parse();

    let _addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let mut shutdown_rx = setup_shutdown_receiver()?;


    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                println!("Received shutdown signal, stopping...");
                break;
            }
        }
    }

    Ok(())
}



