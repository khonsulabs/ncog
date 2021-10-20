use std::{path::PathBuf, str::FromStr};

use bonsaidb::{
    client::{fabruic::Certificate, url::Url, Client},
    core::{
        custodian_password::{ClientConfig, ClientRegistration},
        PASSWORD_CONFIG,
    },
};
use crossterm::{
    event::{Event, KeyCode, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use ncog_encryption::{PrivateKey, PublicKey, Signature};
use structopt::StructOpt;

use crate::server::{Ncog, Request, Response};

#[derive(StructOpt, Debug)]
pub enum Args {
    Db(bonsaidb::cli::Args<Ncog>),
    Account(AccountArgs),
    Key(KeyCommand),
}

#[derive(StructOpt, Debug)]
pub struct AccountArgs {
    pub domain: Option<String>,
    pub certificate: Option<PathBuf>,
    #[structopt(subcommand)]
    pub command: AccountCommand,
}

#[derive(StructOpt, Debug)]
pub enum AccountCommand {
    Register { username: String },
    RegisterKey { path: PathBuf, username: String },
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
            AccountCommand::RegisterKey { .. } => todo!(),
        }
    }
}

#[derive(StructOpt, Debug)]
pub enum KeyCommand {
    New {
        private_key_path: PathBuf,
    },
    ExportPublic {
        private_key_path: PathBuf,
        key_kind: KeyOperation,
        export_path: Option<PathBuf>,
    },
    Sign {
        private_key_path: PathBuf,
        message: PathBuf,
        signature_path: Option<PathBuf>,
    },
    Verify {
        public_key_path: PathBuf,
        message: PathBuf,
        signature_path: PathBuf,
    },
}

impl KeyCommand {
    pub fn execute(self) -> anyhow::Result<()> {
        match self {
            KeyCommand::New { private_key_path } => {
                if private_key_path.exists() {
                    anyhow::bail!("file already exists at path '{:?}'", private_key_path);
                }

                let key = PrivateKey::random();
                let pem = key.to_pem();

                std::fs::write(&private_key_path, pem.as_bytes())?;

                println!(
                    "New key written to {:?}\n{}\n{}",
                    private_key_path,
                    key.public_signing_key().to_pem(),
                    key.public_encryption_key().to_pem()
                );

                Ok(())
            }
            KeyCommand::ExportPublic {
                private_key_path,
                key_kind,
                export_path,
            } => {
                let private_key = std::fs::read(&private_key_path)?;
                let private_key = PrivateKey::from_pem(&private_key)?;
                let public_key = match key_kind {
                    KeyOperation::Sign => private_key.public_signing_key(),
                    KeyOperation::Encrypt => private_key.public_encryption_key(),
                };
                if let Some(export_path) = export_path {
                    std::fs::write(&export_path, public_key.to_pem().as_bytes())?;
                } else {
                    println!("{}", public_key.to_pem());
                }
                Ok(())
            }
            KeyCommand::Sign {
                private_key_path,
                message,
                signature_path,
            } => {
                let private_key = std::fs::read(&private_key_path)?;
                let private_key = PrivateKey::from_pem(&private_key)?;
                let message = std::fs::read(&message)?;
                let signature = private_key.sign(&message)?;
                if let Some(signature_path) = signature_path {
                    std::fs::write(&signature_path, signature.to_pem().as_bytes())?;
                } else {
                    println!("{}", signature.to_pem());
                }
                Ok(())
            }
            KeyCommand::Verify {
                public_key_path,
                message,
                signature_path,
            } => {
                let public_key = std::fs::read(&public_key_path)?;
                let public_key = PublicKey::from_pem(&public_key)?;
                let signature = std::fs::read(&signature_path)?;
                let signature = Signature::from_pem(&signature)?;
                let message = std::fs::read(&message)?;
                public_key.verify(&signature, &message)?;
                println!("Signature verified successfully");
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub enum KeyOperation {
    Sign,
    Encrypt,
}

impl FromStr for KeyOperation {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "sign" || s == "signing" {
            Ok(Self::Sign)
        } else if s == "encrypt" || s == "encryption" {
            Ok(Self::Encrypt)
        } else {
            anyhow::bail!("invalid key kind")
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
