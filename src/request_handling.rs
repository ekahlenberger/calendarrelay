use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{header, HeaderMap, Method, Request, Response, StatusCode};
use sha256::digest;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use crate::Config;
use crate::error::AppError;

const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

pub async fn handle_req(req: Request<Incoming>, config: Arc<Config>) -> Result<Response<Full<Bytes>>, Infallible> {

    let path = req.uri().path().trim_start_matches('/');
    if path.len() < 64 {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("invalid id")))
            .unwrap())
    }

    let id = path[..64].to_string();
    let method = req.method();

    println!("handling request for {}", path);

    return match *method {
        Method::POST => handle_post(req, &config, &id).await,
        Method::GET =>{
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("Failed to decode Base64 path")))
                .unwrap())
        }
        _ => {
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("Failed to decode Base64 path")))
                .unwrap())
        }
    }
}

async fn handle_post(req: Request<Incoming>, config: &Arc<Config>, id: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    let headers = req.headers();

    // Check Authorization header
    if !authorize(headers, &config.push_authorization) {
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Full::new(Bytes::from("Unauthorized")))
            .unwrap());
    }

    let hashed = digest(id);
    let limited_body = Limited::new(req.into_body(), MAX_BODY_SIZE);
    let data = match limited_body.collect().await {
        Ok(data) => data.to_bytes(),
        Err(err) => {
            if err.is::<hyper::Error>() && err.to_string().contains("body limit exceeded") {
                return Ok(Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Full::new(Bytes::from("Request body too large")))
                    .unwrap());
            } else {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from("Failed to read request body")))
                    .unwrap());
            }
        }
    };

    let file_path = config.data_dir.join(hashed);
    match write_to_file(file_path, data).await {
        Ok(_) => Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from("Calendar written")))
            .unwrap()),
        Err(_) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::new(Bytes::from("Failed to write data to file")))
            .unwrap()),
    }
}

async fn write_to_file<P: AsRef<Path>>(path: P, data: Bytes) -> Result<(), AppError> {
    let mut file = File::create(path).await?;
    file.write_all(&data).await?;
    file.flush().await?;
    Ok(())
}

fn authorize(headers: &HeaderMap, expected_authorization_value: &str) -> bool {
    if let Some(auth_value) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_value.to_str() {
            return auth_str == expected_authorization_value;
        }
    }
    false
}