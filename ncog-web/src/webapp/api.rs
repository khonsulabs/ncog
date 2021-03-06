use basws_yew::{prelude::*, ClientLogic, ClientState, Error};
use ncog_shared::{ncog_protocol_version, NcogRequest, NcogResponse, UserProfile};
use url::Url;
use yew::Callback;
use yew_router::{agent::RouteRequest, prelude::Route, prelude::RouteAgentBridge};

pub type AgentMessage = basws_yew::AgentMessage<NcogRequest>;
pub type AgentResponse = basws_yew::AgentResponse<NcogResponse>;
pub type ApiAgent = basws_yew::ApiAgent<NcogApiAgent>;
pub type ApiBridge = basws_yew::ApiBridge<NcogApiAgent>;

#[derive(Debug, Default)]
pub struct NcogApiAgent {
    profile: Option<UserProfile>,
}

impl ClientLogic for NcogApiAgent {
    type Request = NcogRequest;
    type Response = NcogResponse;

    #[cfg(debug_assertions)]
    fn server_url(&self) -> Url {
        Url::parse("ws://localhost:7878/v1/ws").unwrap()
    }

    #[cfg(not(debug_assertions))]
    fn server_url(&self) -> Url {
        Url::parse("wss://api.ncog.id/v1/ws").unwrap()
    }

    fn protocol_version(&self) -> Version {
        ncog_protocol_version()
    }

    fn state_changed(&self, _state: &ClientState) -> anyhow::Result<()> {
        Ok(())
    }

    fn response_received(
        &mut self,
        response: Self::Response,
        _original_request_id: Option<u64>,
    ) -> anyhow::Result<()> {
        match response {
            NcogResponse::AuthenticateAtUrl { url } => {
                let window = web_sys::window().expect("Need a window");
                window
                    .location()
                    .set_href(&url)
                    .expect("Error setting location for redirect");
            }
            NcogResponse::Error { message } => error!("Error from server: {:?}", message),
            NcogResponse::Authenticated(user) => {
                self.profile = Some(user.profile);

                let window = web_sys::window().expect("Need a window");
                if let Ok(path) = window.location().pathname() {
                    if path.contains("/login") {
                        let mut agent = RouteAgentBridge::new(Callback::noop());
                        agent.send(RouteRequest::ReplaceRoute(Route::new_no_state("/")));
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_error(&self, error: Error) -> anyhow::Result<()> {
        error!("Received error: {:?}", error);
        Ok(())
    }
}
