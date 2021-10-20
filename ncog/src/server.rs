use std::collections::HashMap;

use actionable::Actionable;
use async_trait::async_trait;
use bonsaidb::{
    core::{
        connection::ServerConnection,
        custodian_password::{RegistrationFinalization, RegistrationRequest, RegistrationResponse},
        custom_api::CustomApi,
        permissions::{Dispatcher, Permissions},
        schema::Collection,
    },
    server::{Backend, ConnectedClient, CustomServer, ServerDatabase},
};
use ncog_encryption::PublicKey;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::schema::{EncryptedKeyMethod, Identity, IdentityKey, Keyserver};

#[derive(Debug, Dispatcher)]
#[dispatcher(input = Request)]
pub struct Ncog {
    pending_registration_user_id: Option<u64>,
    server: CustomServer<Self>,
    client: ConnectedClient<Self>,
}

#[async_trait]
impl Backend for Ncog {
    type CustomApi = Self;

    type CustomApiDispatcher = Self;

    fn dispatcher_for(
        server: &CustomServer<Self>,
        client: &ConnectedClient<Self>,
    ) -> Self::CustomApiDispatcher {
        Self {
            server: server.clone(),
            client: client.clone(),
            pending_registration_user_id: None,
        }
    }

    async fn initialize(server: &CustomServer<Self>) {
        server.register_schema::<Keyserver>().await.unwrap();
        match server.create_database::<Keyserver>("keyserver").await {
            Ok(_) | Err(bonsaidb::core::Error::DatabaseNameAlreadyTaken(_)) => {}
            Err(err) => unreachable!("unexpected error creating database: {:?}", err),
        }
    }
}

impl CustomApi for Ncog {
    type Request = Request;

    type Response = Response;
}

#[derive(Debug, Serialize, Deserialize, Actionable)]
#[allow(clippy::large_enum_variant)]
pub enum Request {
    #[actionable(protection = "none")]
    RegisterAccount {
        handle: String,
        password_request: RegistrationRequest,
    },
    #[actionable(protection = "none")]
    FinishPasswordRegistration {
        handle: String,
        password_finalization: RegistrationFinalization,
    },
    #[actionable(protection = "none")]
    ChangePassword {
        password_request: RegistrationRequest,
    },
    #[actionable(protection = "none")]
    RegisterKey {
        identity_id: u64,
        expires_at: Option<OffsetDateTime>,
        encrypted_keys: Option<HashMap<EncryptedKeyMethod, Vec<u8>>>,
        public_signing_key: Option<PublicKey>,
        public_encryption_key: Option<PublicKey>,
    },
    #[actionable(protection = "none")]
    StoreEncryptedKey {
        id: u64,
        method: EncryptedKeyMethod,
        encrypted_key: Vec<u8>,
    },
    #[actionable(protection = "none")]
    RevokeKey { id: u64 },
    #[actionable(protection = "none")]
    ListKeys,
    // ListIdentities,
    #[actionable(protection = "none")]
    GetKey(u64),
    #[actionable(protection = "none")]
    ValidateSigningKey(PublicKey),
    #[actionable(protection = "none")]
    ValidateEncryptionKey(PublicKey),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    Ok, // TODO this should be able to use bonsaidb's Ok, maybe?
    FinishPasswordRegistation(RegistrationResponse),
    KeyRegistered {
        id: u64,
        public_signing_key: Option<PublicKey>,
        public_encryption_key: Option<PublicKey>,
    },
    RevokeKey {
        id: u64,
    },
    ListKeys(Vec<IdentityKey>),
    Key(IdentityKey),
    KeyValidation {
        key: PublicKey,
        handle: String,
        registered_at: OffsetDateTime,
        expires_at: OffsetDateTime,
        revoked_at: Option<OffsetDateTime>,
    },
}

impl Ncog {
    pub async fn database(
        &self,
    ) -> Result<ServerDatabase<'_, Self, Keyserver>, bonsaidb::server::Error> {
        self.server.database::<Keyserver>("keyserver").await
    }
}

impl RequestDispatcher for Ncog {
    type Output = Response;
    type Error = anyhow::Error;
}

#[async_trait]
impl RegisterKeyHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
        identity_id: u64,
        expires_at: Option<OffsetDateTime>,
        encrypted_keys: Option<HashMap<EncryptedKeyMethod, Vec<u8>>>,
        public_signing_key: Option<PublicKey>,
        public_encryption_key: Option<PublicKey>,
    ) -> Result<Response, anyhow::Error> {
        if let Some(user_id) = self.client.user_id().await {
            let db = self.database().await?;
            let identity = Identity::get(identity_id, &db)
                .await?
                .ok_or_else(|| anyhow::anyhow!("invalid identity id"))?;
            if identity.contents.user_id != Some(user_id) {
                anyhow::bail!("invalid identity id");
            }

            todo!()
        } else {
            anyhow::bail!("cannot register a key before logging in")
        }
    }
}

#[async_trait]
impl StoreEncryptedKeyHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
        id: u64,
        method: EncryptedKeyMethod,
        encrypted_key: Vec<u8>,
    ) -> Result<Response, anyhow::Error> {
        if let Some(user_id) = self.client.user_id().await {
            todo!()
        } else {
            anyhow::bail!("cannot store a key before logging in")
        }
    }
}

#[async_trait]
impl RevokeKeyHandler for Ncog {
    async fn handle(&self, _permissions: &Permissions, id: u64) -> Result<Response, anyhow::Error> {
        if let Some(user_id) = self.client.user_id().await {
            todo!()
        } else {
            anyhow::bail!("cannot revoke a key before logging in")
        }
    }
}

#[async_trait]
impl GetKeyHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
        key_id: u64,
    ) -> Result<Response, anyhow::Error> {
        if let Some(user_id) = self.client.user_id().await {
            todo!()
        } else {
            anyhow::bail!("cannot get a key before logging in")
        }
    }
}

#[async_trait]
impl ListKeysHandler for Ncog {
    async fn handle(&self, _permissions: &Permissions) -> Result<Response, anyhow::Error> {
        if let Some(user_id) = self.client.user_id().await {
            todo!()
        } else {
            anyhow::bail!("cannot list keys before logging in")
        }
    }
}

#[async_trait]
impl ValidateSigningKeyHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
        public_key: PublicKey,
    ) -> Result<Response, anyhow::Error> {
        todo!()
    }
}

#[async_trait]
impl ValidateEncryptionKeyHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
        public_key: PublicKey,
    ) -> Result<Response, anyhow::Error> {
        todo!()
    }
}

// TODO refactor this to take an initial IdentityKey so that if the process
// fails, it can be resumed by verifying the public key matches.
#[async_trait]
impl RegisterAccountHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
        handle: String,
        password_request: RegistrationRequest,
    ) -> Result<Response, anyhow::Error> {
        // The identity handle space is more limited than the username space, so we need to reserve the identity first.
        let identity = Identity {
            user_id: None,
            handle,
            backup_keys: vec![],
        };
        let db = self.database().await?;
        // TODO catch unique key violation and anonymize it.
        let mut identity = identity.insert_into(&db).await?;
        // Create the user to get the user_id
        // TODO catch unique key violation and anonymize it.
        identity.contents.user_id = Some(self.server.create_user(&identity.contents.handle).await?);
        identity.update(&db).await?;

        // Initiate the password process
        let login_response = self
            .server
            .set_user_password(&identity.contents.handle, password_request)
            .await?;
        Ok(Response::FinishPasswordRegistation(login_response))
    }
}

#[async_trait]
impl ChangePasswordHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
        password_request: RegistrationRequest,
    ) -> Result<Response, anyhow::Error> {
        todo!()
    }
}

#[async_trait]
impl FinishPasswordRegistrationHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
        handle: String,
        password_response: RegistrationFinalization,
    ) -> Result<Response, anyhow::Error> {
        self.server
            .finish_set_user_password(handle, password_response)
            .await?;

        Ok(Response::Ok)
    }
}
