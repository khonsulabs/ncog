use async_trait::async_trait;
use axum::{
    error_handling::HandleErrorExt, extract, http::HeaderValue, response::Html, routing::get,
    AddExtensionLayer, Router,
};
use bonsaidb::server::{CustomServer, HttpService, Peer};
use hyper::{header, server::conn::Http, Body, Request, Response, StatusCode};
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};

use crate::server::Ncog;

#[cfg(debug_assertions)]
const PKG_PATH: &str = "./crates/ncog-webapp/pkg";
#[cfg(not(debug_assertions))]
const PKG_PATH: &str = "./pkg";

#[cfg(debug_assertions)]
const STATIC_PATH: &str = "./crates/ncog-webapp/static";
#[cfg(not(debug_assertions))]
const STATIC_PATH: &str = "./static";

#[derive(Debug, Clone)]
pub struct WebServer {
    server: CustomServer<Ncog>,
}

impl WebServer {
    pub const fn new(server: CustomServer<Ncog>) -> Self {
        Self { server }
    }
}

#[async_trait]
impl HttpService for WebServer {
    async fn handle_connection<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    >(
        &self,
        connection: S,
        peer: &Peer,
    ) -> Result<(), S> {
        if let Err(err) = Http::new()
            .serve_connection(connection, self.router(peer))
            .with_upgrades()
            .await
        {
            log::error!("[http] error serving {}: {:?}", peer.address, err);
        }

        Ok(())
    }
}

impl WebServer {
    fn webapp(&self, peer: &Peer) -> Router {
        Router::new()
            .nest(
                "/pkg",
                axum::routing::service_method_routing::get(ServeDir::new(PKG_PATH)).handle_error(
                    |err: std::io::Error| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("unhandled internal error: {}", err),
                        )
                    },
                ),
            )
            .nest(
                "/static",
                axum::routing::service_method_routing::get(ServeDir::new(STATIC_PATH))
                    .handle_error(|err: std::io::Error| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("unhandled internal error: {}", err),
                        )
                    }),
            )
            .route("/ws", get(upgrade_websocket))
            .fallback(axum::routing::get(spa_index))
            // Attach the server and the remote address as extractable data for the /ws route
            .layer(AddExtensionLayer::new(self.server.clone()))
            .layer(AddExtensionLayer::new(peer.clone()))
            .layer(SetResponseHeaderLayer::<_, Body>::if_not_present(
                header::STRICT_TRANSPORT_SECURITY,
                HeaderValue::from_static("max-age=31536000; preload"),
            ))
    }

    #[cfg(debug_assertions)]
    fn router(&self, peer: &Peer) -> Router {
        self.webapp(peer)
    }

    #[cfg(not(debug_assertions))]
    fn router(&self, peer: &Peer) -> Router {
        if peer.secure {
            self.webapp(peer)
        } else {
            Router::new()
                .nest("/", axum::routing::get(redirect_to_https))
                .layer(AddExtensionLayer::new(self.server.clone()))
        }
    }
}

#[cfg(not(debug_assertions))]
async fn redirect_to_https(
    server: extract::Extension<CustomServer<Ncog>>,
    req: hyper::Request<Body>,
) -> hyper::Response<Body> {
    let path = req.uri().path();
    let mut response = hyper::Response::new(Body::empty());
    *response.status_mut() = hyper::StatusCode::PERMANENT_REDIRECT;
    response.headers_mut().insert(
        "Location",
        HeaderValue::from_str(&format!("https://{}{}", server.primary_domain(), path)).unwrap(),
    );
    response
}

async fn upgrade_websocket(
    server: extract::Extension<CustomServer<Ncog>>,
    peer: extract::Extension<Peer>,
    req: Request<Body>,
) -> Response<Body> {
    server.upgrade_websocket(peer.address, req).await
}

#[allow(clippy::unused_async)]
#[cfg(not(debug_assertions))]
async fn spa_index() -> Html<&'static str> {
    Html::from(include_str!("../../ncog-webapp/static/bootstrap.html"))
}

#[allow(clippy::unused_async)]
#[cfg(debug_assertions)]
async fn spa_index() -> Html<String> {
    Html::from(
        tokio::fs::read_to_string("crates/ncog-webapp/static/bootstrap.html")
            .await
            .unwrap(),
    )
}
