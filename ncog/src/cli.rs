use std::{convert::TryFrom, io::stdout, path::PathBuf};

use bonsaidb::{
    client::{fabruic::Certificate, url::Url, Client},
    core::{
        custodian_password::{ClientConfig, ClientRegistration, RegistrationRequest},
        PASSWORD_CONFIG,
    },
};
use crossterm::{
    event::{Event, KeyCode, KeyEvent, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
    tty::IsTty,
};
use structopt::StructOpt;

use crate::server::{Ncog, Request, Response};

#[derive(StructOpt, Debug)]
pub enum Args {
    Db(bonsaidb::cli::Args<Ncog>),
    Account(AccountArgs),
}

#[derive(StructOpt, Debug)]
pub struct AccountArgs {
    pub domain: Option<String>,
    #[structopt(parse(from_os_str))]
    pub certificate: Option<PathBuf>,
    #[structopt(subcommand)]
    pub command: AccountCommand,
}

#[derive(StructOpt, Debug)]
pub enum AccountCommand {
    Register { username: String },
}

impl AccountArgs {
    pub async fn execute(self) -> anyhow::Result<()> {
        let mut client = Client::build(Url::parse(&format!(
            "bonsaidb://{}",
            self.domain.as_deref().unwrap_or("ncog.id")
        ))?)
        .with_custom_api::<Ncog>();

        if let Some(certificate) = &self.certificate {
            let certificate = tokio::fs::read(certificate).await?;
            client = client.with_certificate(Certificate::from_der(certificate)?);
        }

        let ncog = client.finish().await?;

        match self.command {
            AccountCommand::Register { username } => {
                let password = tokio::task::spawn_blocking::<_, anyhow::Result<String>>(|| loop {
                    println!("Enter a password:\r");
                    let password = read_line()?;
                    println!("Enter the same password again:\r");
                    let verify_password = read_line()?;
                    if password == verify_password {
                        break Ok(password);
                    } else {
                        eprintln!("Passwords did not match.\n")
                    }
                })
                .await??;

                let (registration, request) = ClientRegistration::register(
                    &ClientConfig::new(PASSWORD_CONFIG, None)?,
                    password,
                )?;
                let registration_response = match ncog
                    .send_api_request(Request::RegisterAccount {
                        handle: username.clone(),
                        password_request: request,
                    })
                    .await?
                {
                    Response::FinishPasswordRegistation(response) => response,
                    other => unreachable!("unexpected response: {:?}", other),
                };
                println!("Got one response");

                let (file, password_finalization, export_key) =
                    registration.finish(registration_response)?;

                match ncog
                    .send_api_request(Request::FinishPasswordRegistration {
                        handle: username.clone(),
                        password_finalization,
                    })
                    .await?
                {
                    Response::Ok => {}
                    other => unreachable!("unexpected response: {:?}", other),
                };

                println!("User {} registered successfully.", username);
                Ok(())
            }
        }
    }
}

fn read_line() -> anyhow::Result<String> {
    let mut contents = String::new();
    enable_raw_mode()?;
    loop {
        if let Event::Key(event) = crossterm::event::read()? {
            match event.code {
                KeyCode::Char(c) => {
                    if c == 'c' && event.modifiers == KeyModifiers::CONTROL {
                        anyhow::bail!("Cancelling.")
                    } else {
                        contents.push(c);
                    }
                }
                KeyCode::Enter => break,
                _ => {}
            }
        }
    }
    disable_raw_mode()?;

    Ok(contents)
}
