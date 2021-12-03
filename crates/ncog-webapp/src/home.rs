use std::sync::Arc;

use dominator::{clone, events, html, with_node, Dom};
use futures_signals::{
    map_ref,
    signal::{Mutable, Signal, SignalExt},
};
use web_sys::HtmlInputElement;

use crate::App;

pub(crate) fn render(app: &Arc<App>) -> Dom {
    html!("div", {
        .children(&mut [
            html!("div", {
                .class("page-head")
                .children(&mut [
                    html!("h1", {
                        .children(&mut [
                            html!("span", {
                                .class("title")
                                .text("Ncog")
                            }),
                            html!("span", {
                                .class("subtitle")
                                .text("Private and Secure Collaboration")
                            }),
                        ])
                    }),

                ])
            }),
            html!("div", {
                .child_signal(clone!(app => {
                    app.identity.signal_cloned().map(move |identity| {
                        Some(if let Some(identity) = identity {
                            html!("p", {
                                .text(&format!("Welcome back, {}!", identity))
                            })
                        } else {
                            html!("div", {
                                .children(&mut [
                                    html!("h3", {
                                        .text("Sign In")
                                    }),
                                    html!("fieldset", {
                                        .attr("class", "flex two")
                                        .children(&mut [
                                            html!("label", {
                                                .children(&mut [
                                                    html!("input" => HtmlInputElement, {
                                                        .attr("type", "text")
                                                        .attr("placeholder", "Username")

                                                        .with_node!(element => {
                                                            .event(clone!(app => move |_: events::Input| {
                                                                app.sign_in.username.set_neq(element.value());
                                                            }))
                                                        })
                                                    }),
                                                ])
                                            }),
                                            html!("label", {
                                                .children(&mut [
                                                    html!("input" => HtmlInputElement, {
                                                        .attr("type", "password")
                                                        .attr("placeholder", "Password")

                                                        .with_node!(element => {
                                                            .event(clone!(app => move |_: events::Input| {
                                                                app.sign_in.password.set_neq(element.value());
                                                            }))
                                                        })
                                                    }),
                                                ])
                                            })
                                        ])
                                    }),
                                    html!("button", {
                                        .text("Sign In")
                                        .prop_signal("disabled", app.sign_in.can_sign_in().map(|can| !can))
                                    }),
                                ])
                            })
                        })
                    })
                }))
            })
        ])
    })
}

#[derive(Default)]
pub struct SignIn {
    username: Mutable<String>,
    password: Mutable<String>,
}

impl SignIn {
    fn can_sign_in(&self) -> impl Signal<Item = bool> {
        map_ref! {
                let username = self.username.signal_cloned(),
                let password = self.password.signal_cloned() =>
                !username.is_empty() && !password.is_empty()
        }
    }
}
