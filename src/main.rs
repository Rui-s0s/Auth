#![allow(unused)]

use axum::response::IntoResponse;
use axum::extract::{Query, Path};
use axum::{routing::get, Router, response::Html};
use std::net::SocketAddr;
use serde::Deserialize;

#[tokio::main]
async fn main() {
    let app = Router::new()
    .route("/hello2/{name}", get(handler_hello2))
    .route("/hello", get(handler_hello));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("->> LISTENING on {addr}\n");
    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Debug, Deserialize)]
struct HelloParams {
    name: Option<String>,
}

// `/hello?name=Estefi`
async fn handler_hello(Query(params): Query<HelloParams>) -> impl IntoResponse {
    println!("->> {:<12} - handler_hello - {params:?}", "HANDLER");

    let name = params.name.as_deref().unwrap_or("World?");

    Html(format!("Hello <strong>{name}</strong>"))
}

// `/hello2/Mike`
async fn handler_hello2(Path(name): Path<String>) -> impl IntoResponse {
    println!("->> {:<12} - handler_hello2 - {name:?}", "HANDLER");

    Html(format!("Hello <strong>{name}</strong>"))
}