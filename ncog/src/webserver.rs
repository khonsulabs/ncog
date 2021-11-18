use async_trait::async_trait;
use axum::{extract, routing::get, AddExtensionLayer, Router};
use bonsaidb::server::{CustomServer, Peer, StandardTcpProtocols, TcpService};
use hyper::{server::conn::Http, Body, Request, Response};

use crate::server::Ncog;

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
impl TcpService for WebServer {
    type ApplicationProtocols = StandardTcpProtocols;

    async fn handle_connection<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    >(
        &self,
        connection: S,
        peer: &Peer<Self::ApplicationProtocols>,
    ) -> Result<(), S> {
        let server = self.server.clone();
        let app = Router::new()
            .route("/", get(index_handler))
            .route("/ws", get(upgrade_websocket))
            // Attach the server and the remote address as extractable data for the /ws route
            .layer(AddExtensionLayer::new(server))
            .layer(AddExtensionLayer::new(peer.address));

        if let Err(err) = Http::new()
            .serve_connection(connection, app)
            .with_upgrades()
            .await
        {
            log::error!("[http] error serving {}: {:?}", peer.address, err);
        }

        Ok(())
    }
}

#[allow(clippy::unused_async)]
async fn index_handler() -> String {
    String::from("Hello World")
}

async fn upgrade_websocket(
    server: extract::Extension<CustomServer<Ncog>>,
    peer_address: extract::Extension<std::net::SocketAddr>,
    req: Request<Body>,
) -> Response<Body> {
    server.upgrade_websocket(*peer_address, req).await
}
