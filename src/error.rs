use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("IO error: {0}")]
    IO(#[from] io::Error),
    #[error("Decrypt error: {0}")]
    Aes(aes_gcm::Error),
}