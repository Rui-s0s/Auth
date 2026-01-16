#![allow(unused)]

use axum::response::IntoResponse;
use axum::extract::{Query, Path};
use axum::{Router, response::Html};
use axum::routing::{get, get_service};
use std::net::SocketAddr;
use serde::Deserialize;
use tower_http::services::ServeDir;


#[tokio::main]
async fn main() {
    let app = Router::new()
    .merge(routes_hello())
    .fallback_service(routes_static());

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("->> LISTENING on {addr}\n");
    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

fn routes_static() -> Router {
    Router::new().nest_service("/", get_service(ServeDir::new("./")))
}

#[derive(Debug, Deserialize)]
struct HelloParams {
    name: Option<String>,
}

fn routes_hello() -> Router {
    Router::new()
    .route("/hello2/{name}", get(handler_hello2))
    .route("/hello", get(handler_hello))
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