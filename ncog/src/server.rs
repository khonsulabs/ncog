use std::collections::HashMap;

use actionable::Actionable;
use async_trait::async_trait;
use bonsaidb::{
    core::{
        connection::{AccessPolicy, Connection, QueryKey, ServerConnection},
        custodian_password::{RegistrationFinalization, RegistrationRequest, RegistrationResponse},
        custom_api::CustomApi,
        permissions::{Dispatcher, Permissions},
        schema::{Collection, NamedCollection},
    },
    server::{Backend, ConnectedClient, CustomServer, ServerDatabase},
};
use ncog_encryption::PublicKey;
use serde::{Deserialize, Serialize};
use time::{ext::NumericalDuration, OffsetDateTime};

use crate::schema::{
    EncodedPublicKey, EncryptedKeyMethod, Identity, IdentityKey, Keyserver, NonRevokedPublicKeys,
};

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
        handle: String,
        expires_at: Option<OffsetDateTime>,
        encrypted_keys: Option<HashMap<EncryptedKeyMethod, Vec<u8>>>,
        public_keys: Vec<PublicKey>,
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
    ValidatePublicKey(PublicKey),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    Ok, // TODO this should be able to use bonsaidb's Ok, maybe?
    FinishPasswordRegistation(RegistrationResponse),
    KeyRegistered {
        id: u64,
        public_keys: Vec<PublicKey>,
        expires_at: OffsetDateTime,
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
        handle: String,
        expires_at: Option<OffsetDateTime>,
        encrypted_secret_keys: Option<HashMap<EncryptedKeyMethod, Vec<u8>>>,
        public_keys: Vec<PublicKey>,
    ) -> Result<Response, anyhow::Error> {
        if let Some(user_id) = self.client.user_id().await {
            let db = self.database().await?;
            let identity = Identity::load(&handle, &db)
                .await?
                .ok_or_else(|| anyhow::anyhow!("invalid identity id"))?;
            if identity.contents.user_id != Some(user_id) {
                anyhow::bail!("invalid identity id");
            }

            let registered_at = OffsetDateTime::now_utc();
            let expires_at = expires_at.unwrap_or_else(|| registered_at + 26_i64.weeks());

            let registered_key = IdentityKey {
                identity_id: identity.header.id,
                registered_at,
                encrypted_secret_keys,
                expires_at,
                revoked_at: None,
                public_keys: public_keys
                    .iter()
                    .map(|key| (key.kind(), key.clone()))
                    .collect(),
            }
            .insert_into(&db)
            .await?;

            Ok(Response::KeyRegistered {
                id: registered_key.header.id,
                public_keys,
                expires_at,
            })
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
impl ValidatePublicKeyHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
        public_key: PublicKey,
    ) -> Result<Response, anyhow::Error> {
        let db = self.database().await?;
        let identity_key = db
            .query_with_docs::<NonRevokedPublicKeys>(
                Some(QueryKey::Matches(EncodedPublicKey::from(&public_key))),
                AccessPolicy::UpdateBefore,
            )
            .await?;
        if let Some(mapped_document) = identity_key.first() {
            let identity_key = mapped_document.document.contents::<IdentityKey>()?;
            let identity = Identity::get(identity_key.identity_id, &db)
                .await?
                // TODO this shouldn't error -- we should clean up this data.
                .ok_or_else(|| anyhow::anyhow!("key not found"))?;
            Ok(Response::KeyValidation {
                key: public_key,
                handle: identity.contents.handle,
                registered_at: identity_key.registered_at,
                expires_at: identity_key.expires_at,
                revoked_at: identity_key.revoked_at,
            })
        } else {
            anyhow::bail!("key not found")
        }
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
        let db = self.database().await?;

        // Initiate the password process
        let login_response = register_account(&self.server, &db, handle, password_request).await?;
        Ok(Response::FinishPasswordRegistation(login_response))
    }
}

pub async fn register_account<S: ServerConnection, C: Connection>(
    server: &S,
    db: &C,
    handle: String,
    password_request: RegistrationRequest,
) -> Result<RegistrationResponse, anyhow::Error> {
    // The identity handle space is more limited than the username space, so we need to reserve the identity first.
    let identity = Identity {
        user_id: None,
        handle,
        backup_keys: vec![],
    };
    // TODO catch unique key violation and anonymize it.
    let mut identity = identity.insert_into(db).await?;
    // Create the user to get the user_id
    // TODO catch unique key violation and anonymize it.
    identity.contents.user_id = Some(server.create_user(&identity.contents.handle).await?);
    identity.update(db).await?;

    // Initiate the password process
    let login_response = server
        .set_user_password(&identity.contents.handle, password_request)
        .await?;
    Ok(login_response)
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
