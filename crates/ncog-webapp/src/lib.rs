mod home;

use std::{str::FromStr, sync::Arc};

use bonsaidb::client::url::Url;
use dominator::{clone, html, link, routing, Dom};
use futures_signals::signal::{Mutable, SignalExt};
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    Home,
    // Completed,
    NotFound(String),
}

impl Route {
    // This could use more advanced URL parsing, but it isn't needed
    pub fn from_url(url: &str) -> Self {
        let url = match Url::from_str(url) {
            Ok(url) => url,
            Err(_) => return Route::NotFound(url.to_string()),
        };
        match url.path() {
            "/" => Route::Home,
            other => Route::NotFound(other.to_string()),
        }
    }

    pub fn to_url(&self) -> &str {
        match self {
            Route::Home => "/",
            Route::NotFound(other) => other,
        }
    }

    pub fn render(self, app: &Arc<App>) -> Option<Dom> {
        match self {
            Route::Home => Some(home::render(app)),
            Route::NotFound(path) => Some(html!("div", {
                .text(&format!("The content ({}) you are looking for cannot be found.", path))
            })),
        }
    }
}

impl Default for Route {
    fn default() -> Self {
        // Create the Route based on the current URL
        Self::from_url(&routing::url().lock_ref())
    }
}

struct App {
    identity: Mutable<Option<String>>,
    route: Mutable<Route>,
    sign_in: home::SignIn,
}

impl App {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            identity: Mutable::new(None),
            route: Mutable::new(Route::default()),
            sign_in: home::SignIn::default(),
        })
    }

    fn render(app: Arc<Self>) -> Dom {
        // Create the DOM nodes
        html!("div", {
            .class("content")

            .future(routing::url().signal_ref(|url| Route::from_url(url)).for_each(clone!(app => move |route| {
                app.route.set_neq(route);
                async{}
            })))

            .children(&mut [
                html!("nav", {
                    .children(&mut [
                        link!(Route::Home.to_url(), {
                            .class("brand")
                            .children(&mut [
                                html!("img", {
                                    .class("logo")
                                    .attr("src", "/static/icon.svg")
                                }),
                                html!("span", {
                                    .text("Ncog")
                                })
                            ])
                        }),

                        html!("input", {
                            .attr("id", "bmenub")
                            .attr("type", "checkbox")
                            .class("show")
                        }),

                        html!("label", {
                            .attr("for", "bmenub")
                            .attr("class", "burger pseudo button")
                            .text("\u{02261}")
                        }),

                        html!("div", {
                            .class("menu")
                            .children(&mut [
                                link!(Route::Home.to_url(), {
                                    .attr("class", "pseudo button")
                                    .text("Home")
                                    .class_signal("active", app.route.signal_cloned().map(move |x| x == Route::Home))
                                })
                            ])
                        })
                    ])
                }),

                html!("div", {
                    .child_signal(clone!(app => {
                        app.route.signal_cloned().map(move |route| {
                            route.render(&app)
                        })
                    }))
                }),
            ])
        })
    }
}

#[wasm_bindgen(start)]
pub fn main_js() -> Result<(), JsValue> {
    #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();

    let app = App::new();
    dominator::append_dom(&dominator::body(), App::render(app));

    Ok(())
}
