use tokio::signal;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::oneshot;
use tokio::sync::oneshot::{Receiver, Sender};
use crate::error::AppError;


pub fn setup_shutdown_receiver() -> Result<Receiver<()>, AppError> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    tokio::task::spawn(wait_for_shutdown_signals(shutdown_tx));
    return Ok(shutdown_rx);
}
async fn wait_for_shutdown_signals(shutdown_tx: Sender<()>) {
    println!("Waiting for shutdown signals...");

    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to listen for SIGINT");
        println!("Received SIGINT");
    };

    let sigterm = async {
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to listen for SIGTERM");
        sigterm.recv().await;
        println!("Received SIGTERM");
    };

    // Wait for either SIGINT or SIGTERM
    tokio::select! {
        _ = ctrl_c => { println!("Ctrl+C pressed (SIGINT)"); },
        _ = sigterm => { println!("Terminate signal received (SIGTERM)"); },
    }

    println!("Sending shutdown signal...");
    let _ = shutdown_tx.send(());
}