use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

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
use ncog_encryption::{EncryptedPayload, PublicKey, SecretKey, Signature};
use structopt::StructOpt;

use crate::server::{Ncog, Request, Response};

#[derive(StructOpt, Debug)]
pub enum Args {
    Db(bonsaidb::cli::Args<Ncog>),
    Account(AccountArgs),
    Key(KeyCommand),
}

impl Args {
    pub async fn execute(self) -> Result<(), anyhow::Error> {
        match self {
            Args::Db(command) => command.execute().await,
            Args::Account(command) => command.execute().await,
            Args::Key(command) => command.execute(),
        }
    }
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
                    }

                    eprintln!("Passwords did not match. Please try again.\n");
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
        #[structopt(name = "out-file", short, long)]
        secret_key_path: PathBuf,
    },
    ExportPublic {
        key_kind: KeyOperation,
        #[structopt(name = "secret-key", short, long)]
        secret_key_path: PathBuf,
        #[structopt(name = "out-file", short, long)]
        export_path: Option<PathBuf>,
    },
    Sign {
        #[structopt(name = "secret-key", short, long)]
        secret_key_path: PathBuf,
        #[structopt(name = "in-file", short, long)]
        message: PathBuf,
        #[structopt(name = "out-file", short, long)]
        signature_path: Option<PathBuf>,
    },
    Verify {
        #[structopt(name = "public-key", short, long)]
        public_key_path: PathBuf,
        #[structopt(name = "in-file", short, long)]
        message: PathBuf,
        #[structopt(name = "signature", short, long)]
        signature_path: PathBuf,
    },
    Encrypt {
        #[structopt(name = "recipient-public-key", short = "p", long)]
        recipient_public_key_path: PathBuf,
        #[structopt(name = "in-file", short, long)]
        plaintext_path: PathBuf,
        #[structopt(name = "out-file", short, long)]
        encrypted_path: PathBuf,
        #[structopt(name = "sender-secret-key", short, long)]
        sender_secret_key_path: Option<PathBuf>,
    },
    Decrypt {
        #[structopt(name = "secret-key", short, long)]
        secret_key_path: PathBuf,
        #[structopt(name = "in-file", short, long)]
        encrypted_path: PathBuf,
        #[structopt(name = "out-file", short, long)]
        plaintext_path: PathBuf,
    },
}

impl KeyCommand {
    pub fn execute(self) -> anyhow::Result<()> {
        match self {
            KeyCommand::New { secret_key_path } => new_key(&secret_key_path),
            KeyCommand::ExportPublic {
                secret_key_path,
                key_kind,
                export_path,
            } => export_public_key(&secret_key_path, &key_kind, export_path.as_deref()),

            KeyCommand::Sign {
                secret_key_path,
                message,
                signature_path,
            } => {
                let secret_key = std::fs::read(&secret_key_path)?;
                let secret_key = SecretKey::from_pem(&secret_key)?;
                let message = std::fs::read(&message)?;
                let signature = secret_key.sign(&message)?;
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
            KeyCommand::Encrypt {
                recipient_public_key_path,
                sender_secret_key_path,
                plaintext_path,
                encrypted_path,
            } => {
                let recipient_public_key = std::fs::read(&recipient_public_key_path)?;
                let recipient_public_key = PublicKey::from_pem(&recipient_public_key)?;

                let sender_secret_key = if let Some(sender_secret_key_path) = sender_secret_key_path
                {
                    let secret_key = std::fs::read(&sender_secret_key_path)?;
                    Some(SecretKey::from_pem(&secret_key)?)
                } else {
                    None
                };

                let plaintext = std::fs::read(&plaintext_path)?;
                let encrypted = recipient_public_key
                    .encrypt_for(
                        plaintext,
                        Vec::new(),
                        Vec::new(),
                        sender_secret_key.as_ref(),
                    )?
                    .to_bytes();

                std::fs::write(&encrypted_path, &encrypted)?;

                println!("Encrypted file written to {:?}", encrypted_path);
                Ok(())
            }
            KeyCommand::Decrypt {
                secret_key_path,
                encrypted_path,
                plaintext_path,
            } => {
                let secret_key = std::fs::read(&secret_key_path)?;
                let secret_key = SecretKey::from_pem(&secret_key)?;

                let encrypted = std::fs::read(&encrypted_path)?;
                let encrypted = EncryptedPayload::from_bytes(&encrypted)?;

                let plaintext = secret_key.decrypt(&encrypted)?;

                std::fs::write(&plaintext_path, &plaintext)?;
                println!("Decrypted file written to {:?}.", plaintext_path);
                if let Some(sender) = &encrypted.sender {
                    println!("Encrypted by public key:\n{}", sender.to_pem());
                }
                Ok(())
            }
        }
    }
}

fn new_key(secret_key_path: &Path) -> anyhow::Result<()> {
    if secret_key_path.exists() {
        anyhow::bail!("file already exists at path '{:?}'", secret_key_path);
    }

    let key = SecretKey::random();
    let pem = key.to_pem();

    std::fs::write(&secret_key_path, pem.as_bytes())?;

    println!(
        "New key written to {:?}\n{}\n{}",
        secret_key_path,
        key.public_signing_key().to_pem(),
        key.public_encryption_key().to_pem()
    );

    Ok(())
}

fn export_public_key(
    secret_key_path: &Path,
    key_kind: &KeyOperation,
    export_path: Option<&Path>,
) -> anyhow::Result<()> {
    let secret_key = std::fs::read(&secret_key_path)?;
    let secret_key = SecretKey::from_pem(&secret_key)?;
    let public_key = match key_kind {
        KeyOperation::Sign => secret_key.public_signing_key(),
        KeyOperation::Encrypt => secret_key.public_encryption_key(),
    };
    if let Some(export_path) = export_path {
        std::fs::write(export_path, public_key.to_pem().as_bytes())?;
    } else {
        println!("{}", public_key.to_pem());
    }
    Ok(())
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
                    }

                    contents.push(c);
                }
                KeyCode::Enter => break,
                _ => {}
            }
        }
    }
    disable_raw_mode()?;

    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! os_args {
        ($($arg:expr),* $(,)?) => {{
            vec![$(std::ffi::OsString::from($arg)),*]
        }}
    }

    #[tokio::test]
    async fn fully_local_encryption() -> anyhow::Result<()> {
        // Test sending a payload from bob to alice.
        let test_directory = tempfile::tempdir()?;
        let alice_secret_key = test_directory.path().join("alice.key");
        Args::from_iter(os_args![
            "ncog",
            "key",
            "new",
            "--out-file",
            &alice_secret_key
        ])
        .execute()
        .await?;

        let alice_public_key = test_directory.path().join("alice.pub");
        Args::from_iter(os_args![
            "ncog",
            "key",
            "export-public",
            "encryption",
            "--secret-key",
            &alice_secret_key,
            "--out-file",
            &alice_public_key,
        ])
        .execute()
        .await?;

        let bob_secret_key = test_directory.path().join("bob.key");
        Args::from_iter(os_args![
            "ncog",
            "key",
            "new",
            "--out-file",
            &bob_secret_key,
        ])
        .execute()
        .await?;

        let plaintext = test_directory.path().join("plaintext-input");
        std::fs::write(&plaintext, b"hello world")?;
        let ciphertext = test_directory.path().join("ciphertext");
        Args::from_iter(os_args![
            "ncog",
            "key",
            "encrypt",
            "--in-file",
            &plaintext,
            "--out-file",
            &ciphertext,
            "--recipient-public-key",
            &alice_public_key,
            "--sender-secret-key",
            &bob_secret_key,
        ])
        .execute()
        .await?;
        let ciphertext_bytes = std::fs::read(&ciphertext)?;
        assert_ne!(ciphertext_bytes, b"hello world");

        let result = test_directory.path().join("plaintext-output");
        Args::from_iter(os_args![
            "ncog",
            "key",
            "decrypt",
            "--in-file",
            &ciphertext,
            "--out-file",
            &result,
            "--secret-key",
            &alice_secret_key,
        ])
        .execute()
        .await?;
        let result_bytes = std::fs::read(&result)?;
        assert_eq!(result_bytes, b"hello world");

        Ok(())
    }

    #[tokio::test]
    async fn fully_local_signing() -> anyhow::Result<()> {
        // Test signing a payload by alice
        let test_directory = tempfile::tempdir()?;
        let alice_secret_key = test_directory.path().join("alice.key");
        Args::from_iter(os_args![
            "ncog",
            "key",
            "new",
            "--out-file",
            &alice_secret_key
        ])
        .execute()
        .await?;

        let alice_public_key = test_directory.path().join("alice.pub");
        Args::from_iter(os_args![
            "ncog",
            "key",
            "export-public",
            "signing",
            "--secret-key",
            &alice_secret_key,
            "--out-file",
            &alice_public_key,
        ])
        .execute()
        .await?;

        let message = test_directory.path().join("message");
        std::fs::write(&message, b"hello world")?;
        let signature = test_directory.path().join("signature");
        Args::from_iter(os_args![
            "ncog",
            "key",
            "sign",
            "--in-file",
            &message,
            "--out-file",
            &signature,
            "--secret-key",
            &alice_secret_key,
        ])
        .execute()
        .await?;

        Args::from_iter(os_args![
            "ncog",
            "key",
            "verify",
            "--in-file",
            &message,
            "--signature",
            &signature,
            "--public-key",
            &alice_public_key,
        ])
        .execute()
        .await?;

        Ok(())
    }
}
