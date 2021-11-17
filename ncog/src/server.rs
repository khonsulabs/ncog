use std::collections::HashMap;

use actionable::{Action, Actionable, ResourceName};
use async_trait::async_trait;
use bonsaidb::{
    core::{
        connection::{AccessPolicy, Connection, QueryKey, ServerConnection},
        custodian_password::{RegistrationFinalization, RegistrationRequest, RegistrationResponse},
        custom_api::CustomApi,
        permissions::{Dispatcher, Permissions},
        schema::Collection,
    },
    server::{
        Backend, BackendError, ConnectedClient, CustomApiDispatcher, CustomServer, ServerDatabase,
    },
};
use ncog_encryption::{Error, PublicKey};
use serde::{Deserialize, Serialize};
use time::{ext::NumericalDuration, OffsetDateTime};

use crate::schema::{
    EncodedPublicKey, EncryptedKeyMethod, Identity, IdentityKey, Invitation, Keyserver,
    NonRevokedPublicKeys,
};

#[derive(Debug, Dispatcher)]
#[dispatcher(input = Request)]
pub struct Ncog {
    pending_registration_user_id: Option<u64>,
    server: CustomServer<Self>,
    client: ConnectedClient<Self>,
}

#[derive(Clone, Debug)]
pub struct NcogClient {}

#[async_trait]
impl Backend for Ncog {
    type CustomApi = Self;
    type CustomApiDispatcher = Self;
    type ClientData = NcogClient;

    async fn initialize(server: &CustomServer<Self>) {
        server.register_schema::<Keyserver>().await.unwrap();
        server
            .create_database::<Keyserver>("keyserver", true)
            .await
            .unwrap();
    }
}

impl CustomApiDispatcher<Self> for Ncog {
    fn new(server: &CustomServer<Self>, client: &ConnectedClient<Self>) -> Self {
        Self {
            server: server.clone(),
            client: client.clone(),
            pending_registration_user_id: None,
        }
    }
}

impl CustomApi for Ncog {
    type Request = Request;
    type Response = Response;
    type Error = KeyserverError;
}

#[derive(Debug, Serialize, Deserialize, Clone, thiserror::Error)]
pub enum KeyserverError {
    #[error("authentication required")]
    AuthenticationRequired,
    #[error("unknown identity")]
    UnknownIdentity,
    #[error("unknown key")]
    UnknownKey,
    #[error("unknown invitation")]
    UnknownInvitation,
    #[error("expired invitation")]
    ExpiredInvitation,
    #[error("encryption error: {0}")]
    Encryption(String),
}

impl From<Error> for KeyserverError {
    fn from(err: Error) -> Self {
        Self::Encryption(err.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TrustLevel {
    Highest,
    High,
    Low,
    None,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum RedemptionLimit {
    Some(u32),
    Unlimited,
}

impl Default for RedemptionLimit {
    fn default() -> Self {
        Self::Some(1)
    }
}

#[derive(Debug, Serialize, Deserialize, Actionable)]
#[allow(clippy::large_enum_variant)]
pub enum Request {
    #[actionable(protection = "simple")]
    CreateInvitation {
        handle: String,
        trust_level: TrustLevel,
        expires_at: Option<OffsetDateTime>,
        max_redemptions: Option<RedemptionLimit>,
    },
    #[actionable(protection = "none")]
    RegisterAccount {
        handle: String,
        invitation: u64,
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
    Ok,
    FinishPasswordRegistation(RegistrationResponse),
    InvitationCreated {
        token: u64,
        expires_at: Option<OffsetDateTime>,
        max_redemptions: Option<RedemptionLimit>,
    },
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
    pub async fn database(&self) -> Result<ServerDatabase<Self>, bonsaidb::core::Error> {
        self.server.database::<Keyserver>("keyserver").await
    }
}

impl RequestDispatcher for Ncog {
    type Output = Response;
    type Error = BackendError<KeyserverError>;
}

#[async_trait]
impl CreateInvitationHandler for Ncog {
    type Action = NcogAction;

    async fn resource_name<'a>(
        &'a self,
        _handle: &'a String,
        _trust_level: &'a TrustLevel,
        _expires_at: &'a Option<OffsetDateTime>,
        _max_redemptions: &'a Option<RedemptionLimit>,
    ) -> Result<ResourceName<'a>, BackendError<KeyserverError>> {
        Ok(ncog_resource_name())
    }

    fn action() -> Self::Action {
        NcogAction::CreateInvitation
    }

    async fn handle_protected(
        &self,
        _permissions: &Permissions,
        handle: String,
        trust_level: TrustLevel,
        expires_at: Option<OffsetDateTime>,
        max_redemptions: Option<RedemptionLimit>,
    ) -> Result<Response, BackendError<KeyserverError>> {
        if let Some(user_id) = self.client.user_id().await {
            let db = self.database().await?;
            let identity = Identity::load_for_user_id(&handle, user_id, &db).await?;
            let invitation = Invitation {
                token: 0,
                created_by: identity.header.id,
                trust_level,
                expires_at,
                max_redemptions,
            }
            .generate_random_token(&db)
            .await?;
            Ok(Response::InvitationCreated {
                token: invitation.contents.token,
                expires_at: invitation.contents.expires_at,
                max_redemptions: invitation.contents.max_redemptions,
            })
        } else {
            Err(BackendError::Backend(
                KeyserverError::AuthenticationRequired,
            ))
        }
    }
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
    ) -> Result<Response, BackendError<KeyserverError>> {
        if let Some(user_id) = self.client.user_id().await {
            let db = self.database().await?;
            let identity = Identity::load_for_user_id(&handle, user_id, &db).await?;

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
            Err(BackendError::Backend(
                KeyserverError::AuthenticationRequired,
            ))
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
    ) -> Result<Response, BackendError<KeyserverError>> {
        if let Some(user_id) = self.client.user_id().await {
            todo!()
        } else {
            Err(BackendError::Backend(
                KeyserverError::AuthenticationRequired,
            ))
        }
    }
}

#[async_trait]
impl RevokeKeyHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
        id: u64,
    ) -> Result<Response, BackendError<KeyserverError>> {
        if let Some(user_id) = self.client.user_id().await {
            todo!()
        } else {
            Err(BackendError::Backend(
                KeyserverError::AuthenticationRequired,
            ))
        }
    }
}

#[async_trait]
impl GetKeyHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
        key_id: u64,
    ) -> Result<Response, BackendError<KeyserverError>> {
        if let Some(user_id) = self.client.user_id().await {
            todo!()
        } else {
            Err(BackendError::Backend(
                KeyserverError::AuthenticationRequired,
            ))
        }
    }
}

#[async_trait]
impl ListKeysHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
    ) -> Result<Response, BackendError<KeyserverError>> {
        if let Some(user_id) = self.client.user_id().await {
            todo!()
        } else {
            Err(BackendError::Backend(
                KeyserverError::AuthenticationRequired,
            ))
        }
    }
}

#[async_trait]
impl ValidatePublicKeyHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
        public_key: PublicKey,
    ) -> Result<Response, BackendError<KeyserverError>> {
        let db = self.database().await?;
        let identity_key = db
            .view::<NonRevokedPublicKeys>()
            .with_key(EncodedPublicKey::from(&public_key))
            .query_with_docs()
            .await?;
        if let Some(mapped_document) = identity_key.first() {
            let identity_key = mapped_document.document.contents::<IdentityKey>()?;
            let identity = Identity::get(identity_key.identity_id, &db)
                .await?
                .ok_or(BackendError::Backend(KeyserverError::UnknownKey))?;
            Ok(Response::KeyValidation {
                key: public_key,
                handle: identity.contents.handle,
                registered_at: identity_key.registered_at,
                expires_at: identity_key.expires_at,
                revoked_at: identity_key.revoked_at,
            })
        } else {
            Err(BackendError::Backend(KeyserverError::UnknownKey))
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
        invitation: u64,
        password_request: RegistrationRequest,
    ) -> Result<Response, BackendError<KeyserverError>> {
        let db = self.database().await?;

        let invitation = Invitation::load_from_token(invitation, &db).await?;

        if invitation.contents.max_redemptions.is_some() {
            todo!()
        }

        if let Some(expires_at) = invitation.contents.expires_at {
            if expires_at < OffsetDateTime::now_utc() {
                return Err(BackendError::Backend(KeyserverError::ExpiredInvitation));
            }
        }

        // Initiate the password process
        let login_response = register_account(
            &self.server,
            &db,
            handle,
            Some(invitation.header.id),
            password_request,
        )
        .await?;
        Ok(Response::FinishPasswordRegistation(login_response))
    }
}

pub async fn register_account<S: ServerConnection, C: Connection>(
    server: &S,
    db: &C,
    handle: String,
    accepted_invitation_id: Option<u64>,
    password_request: RegistrationRequest,
) -> Result<RegistrationResponse, BackendError<KeyserverError>> {
    // The identity handle space is more limited than the username space, so we need to reserve the identity first.
    let identity = Identity {
        user_id: None,
        accepted_invitation_id,
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
    ) -> Result<Response, BackendError<KeyserverError>> {
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
    ) -> Result<Response, BackendError<KeyserverError>> {
        self.server
            .finish_set_user_password(handle, password_response)
            .await?;

        Ok(Response::Ok)
    }
}

#[must_use]
pub fn ncog_resource_name<'a>() -> ResourceName<'a> {
    ResourceName::named("ncog")
}

#[derive(Action, Serialize, Deserialize, Clone, Copy, Debug)]
pub enum NcogAction {
    CreateInvitation,
}
