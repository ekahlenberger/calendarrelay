use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use base64::Engine;
use base64::engine::general_purpose;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{header, HeaderMap, Method, Request, Response, StatusCode};
use pbkdf2::pbkdf2_hmac;
use sha256::digest;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::Config;
use crate::error::AppError;

const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
const PBKDF2_ITERATIONS: u32 = 1_000_000;
const AES_KEY_SIZE: usize = 32; // 256 bits

pub async fn handle_req(req: Request<Incoming>, config: Arc<Config>) -> Result<Response<Full<Bytes>>, Infallible> {

    let path = req.uri().path().trim_matches('/');
    if path.len() < 64 {
        return response_with_status(StatusCode::BAD_REQUEST, "invalid id");
    }

    let id = &path[..64];
    let hashed = digest(id);
    let method = req.method();

    println!("handling request for {}", path);

    return match *method {
        Method::POST => handle_post(req, &config, &hashed).await,
        Method::GET => handle_get(req, &config, &hashed).await,
        _ => response_with_status(StatusCode::BAD_REQUEST, "Failed to decode Base64 path")
    }
}

async fn handle_post(req: Request<Incoming>, config: &Arc<Config>, hashed_id: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    let headers = req.headers();

    // Check Authorization header
    if !authorize(headers, &config.push_authorization) {
        return response_with_status(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

    let limited_body = Limited::new(req.into_body(), MAX_BODY_SIZE);
    let data = match limited_body.collect().await {
        Ok(data) => data.to_bytes(),
        Err(err) => {
            return if err.is::<hyper::Error>() && err.to_string().contains("body limit exceeded") {
                response_with_status(StatusCode::INTERNAL_SERVER_ERROR, "Request body too large")
            } else {
                response_with_status(StatusCode::INTERNAL_SERVER_ERROR, "Failed to read request body")
            }
        }
    };

    let file_path = config.data_dir.join(hashed_id);
    match write_to_file(file_path, data).await {
        Ok(_) => response_with_ok(Bytes::from("Calendar written"), "text/plain"),
        Err(_) => response_with_status(StatusCode::INTERNAL_SERVER_ERROR, "Failed to write data to file")
    }
}
async fn handle_get(req: Request<Incoming>, config: &Arc<Config>, hashed_id: &str) -> Result<Response<Full<Bytes>>, Infallible>{
    let path = req.uri().path().trim_matches('/');
    let coded_key = &path[64..];

    let key = match general_purpose::STANDARD.decode(coded_key) {
        Ok(decoded_bytes) => decoded_bytes,
        Err(_) => return response_with_status(StatusCode::INTERNAL_SERVER_ERROR, "Failed to decode Base64 key")
    };

    let file_path = config.data_dir.join(hashed_id);
    if !Path::new(&file_path).exists(){
        return response_with_status(StatusCode::INTERNAL_SERVER_ERROR, "The calendar does not exist")
    }
    let data = match read_from_file(file_path).await{
        Ok(data) =>
            match decrypt(&data, &key) {
                Ok(data) =>
                if is_icalendar(&data) {
                    data
                }
                else {
                    return response_with_status(StatusCode::UNPROCESSABLE_ENTITY, "no calendar found")
                }

                Err(_) => return response_with_status(StatusCode::INTERNAL_SERVER_ERROR, "Failed to decrypt data")
            },
        Err(_) => return response_with_status(StatusCode::INTERNAL_SERVER_ERROR, "Failed to read data")
    };

    response_with_ok(Bytes::from(data), "text/calendar")
}
async fn write_to_file<P: AsRef<Path>>(path: P, data: Bytes) -> Result<(), AppError> {
    let mut file = File::create(path).await?;
    file.write_all(&data).await?;
    file.flush().await?;
    Ok(())
}
async fn read_from_file(path: PathBuf) -> Result<Vec<u8>, AppError>{
    let mut file = File::open(path).await?;
    let mut buf= vec![];
    file.read_to_end(&mut buf).await?;
    Ok(buf)
}

fn authorize(headers: &HeaderMap, expected_authorization_value: &str) -> bool {
    if let Some(auth_value) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_value.to_str() {
            return auth_str == expected_authorization_value;
        }
    }
    false
}

fn decrypt(encrypted_data: &[u8], pass: &Vec<u8>) -> Result<Vec<u8>, AppError> {

    let salt = b""; // Ideally, use a unique salt for each user/data
    let mut key = [0u8; AES_KEY_SIZE];
    pbkdf2_hmac::<sha2::Sha256>(pass, salt, PBKDF2_ITERATIONS, &mut key);

    let nonce_size = 12; // 96 bits
    //let tag_size = 16; // 128 bits

    // Split the input data into nonce and ciphertext
    let (nonce, ciphertext) = encrypted_data.split_at(nonce_size);

    // Initialize the key, nonce and cipher
    let key = Key::<Aes256Gcm>::from_slice(&key);
    let nonce = Nonce::from_slice(nonce); // 96-bits; unique per message
    let cipher = Aes256Gcm::new(key);

    // Decrypt the data
    match cipher.decrypt(nonce, ciphertext) {
        Ok(data) => Ok(data),
        Err(err) =>  Err(AppError::Aes(err))
    }
}

fn is_icalendar(data: &[u8]) -> bool {
    let data_str = match std::str::from_utf8(data) {
        Ok(v) => v,
        Err(_) => return false,
    };

    data_str.starts_with("BEGIN:VCALENDAR") && data_str.contains("END:VCALENDAR")
}

fn response_with_status(status: StatusCode, message: &str) -> Result<Response<Full<Bytes>>,Infallible> {
    Ok(Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(message.to_string())))
        .unwrap())
}

fn response_with_ok(content: Bytes, content_type: &str) -> Result<Response<Full<Bytes>>,Infallible> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", content_type)
        .body(Full::new(content))
        .unwrap())
}