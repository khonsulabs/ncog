use std::collections::HashMap;

use actionable::{Action, ResourceName};
use async_trait::async_trait;
use bonsaidb::{
    core::{
        connection::{Connection, StorageConnection},
        custodian_password::{RegistrationFinalization, RegistrationRequest, RegistrationResponse},
        permissions::{Dispatcher, Permissions},
        schema::Collection,
    },
    server::{
        Backend, BackendError, ConnectedClient, CustomApiDispatcher, CustomServer, ServerDatabase,
    },
};
use ncog_encryption::PublicKey;
use ncog_shared::{
    schema::{Identity, IdentityKey, Invitation, Keyserver, NonRevokedPublicKeys},
    ChangePasswordHandler, CreateInvitationHandler, EncryptedKeyMethod,
    FinishPasswordRegistrationHandler, GetKeyHandler, KeyserverError, ListKeysHandler, NcogApi,
    RedemptionLimit, RegisterAccountHandler, RegisterKeyHandler, Request, RequestDispatcher,
    Response, RevokeKeyHandler, StoreEncryptedKeyHandler, TrustLevel, ValidatePublicKeyHandler,
};
use serde::{Deserialize, Serialize};
use time::{ext::NumericalDuration, OffsetDateTime};

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
    type CustomApi = NcogApi;
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
        _id: u64,
        _method: EncryptedKeyMethod,
        _encrypted_key: Vec<u8>,
    ) -> Result<Response, BackendError<KeyserverError>> {
        if let Some(_user_id) = self.client.user_id().await {
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
        _id: u64,
    ) -> Result<Response, BackendError<KeyserverError>> {
        if let Some(_user_id) = self.client.user_id().await {
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
        _key_id: u64,
    ) -> Result<Response, BackendError<KeyserverError>> {
        if let Some(_user_id) = self.client.user_id().await {
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
        if let Some(_user_id) = self.client.user_id().await {
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
            .with_key((public_key.kind(), public_key.to_bytes()))
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

pub async fn register_account<S: StorageConnection, C: Connection>(
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
        _password_request: RegistrationRequest,
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
