use std::collections::HashMap;

use actionable::Actionable;
use async_trait::async_trait;
use bonsaidb::{
    core::{
        admin::password_config::PasswordConfig,
        custodian_password::{RegistrationFinalization, RegistrationRequest},
        custom_api::CustomApi,
        document::Document,
        permissions::{Dispatcher, Permissions},
        schema::{
            Collection, CollectionName, InvalidNameError, MapResult, Name, Schema, SchemaName,
            Schematic, View,
        },
    },
    server::{Backend, ConnectedClient, CustomServer},
};
use ncog_encryption::{Attestation, PublicKey};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use time::OffsetDateTime;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Args::from_args() {
        Args::Db(command) => {
            command
                .execute(|storage| async move {
                    storage.register_schema::<Keyserver>().await?;
                    Ok(())
                })
                .await
        }
    }
}

#[derive(Debug, Dispatcher)]
#[dispatcher(input = Request)]
pub struct Ncog {
    server: CustomServer<Self>,
    client: ConnectedClient<Self>,
}

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
        }
    }
}

impl CustomApi for Ncog {
    type Request = Request;

    type Response = Response;
}

// #[async_trait]
// impl Dispatcher<Request> for Ncog {
//     type Result = Result<Response, anyhow::Error>;

//     async fn dispatch(&self, permissions: &Permissions, request: Request) -> Self::Result {

//     }
// }

#[derive(StructOpt, Debug)]
pub enum Args {
    Db(bonsaidb::cli::Args),
}

#[derive(Debug)]
pub struct Keyserver;

impl Schema for Keyserver {
    fn schema_name() -> Result<bonsaidb::core::schema::SchemaName, InvalidNameError> {
        SchemaName::new(NCOG_AUTHORITY, "keyserver")
    }

    fn define_collections(schema: &mut Schematic) -> Result<(), bonsaidb::core::Error> {
        schema.define_collection::<Identity>()?;
        schema.define_collection::<IdentityKey>()?;
        schema.define_collection::<RegisteredNotarization>()?;
        schema.define_collection::<PasswordConfig>()?;
        Ok(())
    }
}

pub const NCOG_AUTHORITY: &str = "ncog";

#[derive(Debug, Serialize, Deserialize)]
pub struct Identity {
    pub user_id: u64,
    pub handle: String,
    pub backup_keys: Vec<BackupKey>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupKey {
    pub label: String,
    pub created_at: OffsetDateTime,
    pub public_key: PublicKey,
}

impl Collection for Identity {
    fn collection_name() -> Result<CollectionName, InvalidNameError> {
        CollectionName::new(NCOG_AUTHORITY, "identities")
    }

    fn define_views(schema: &mut Schematic) -> Result<(), bonsaidb::core::Error> {
        schema.define_view(IdentityByHandle)
    }
}

#[derive(Debug)]
pub struct IdentityByHandle;

impl View for IdentityByHandle {
    type Collection = Identity;
    type Key = String;
    type Value = ();

    fn unique(&self) -> bool {
        true
    }

    fn version(&self) -> u64 {
        0
    }

    fn name(&self) -> Result<bonsaidb::core::schema::Name, InvalidNameError> {
        Name::new("by-handle")
    }

    fn map(&self, document: &Document<'_>) -> MapResult<Self::Key, Self::Value> {
        let identity = document.contents::<Identity>()?;
        Ok(Some(document.emit_key(identity.handle)))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityKey {
    /// The identity that this key belongs to.
    pub identity_id: u64,
    /// The timestamp this key was registered with this server.
    pub registered_at: OffsetDateTime,
    /// The timestamp this key expires/expired at.
    pub expires_at: OffsetDateTime,
    /// The timestamp this key was revoked at, if any.
    pub revoked_at: Option<OffsetDateTime>,
    /// Optionally stored encrypted versions of the private key.
    pub encrypted_private_keys: Option<HashMap<EncryptedKeyMethod, Vec<u8>>>,
    /// The public signing key, if this key can be used to sign.
    pub public_signing_key: Option<PublicKey>,
    /// The public encryption key, if this key can be used for encryption.
    pub public_encryption_key: Option<PublicKey>,
}

impl Collection for IdentityKey {
    fn collection_name() -> Result<CollectionName, InvalidNameError> {
        CollectionName::new(NCOG_AUTHORITY, "identity-keys")
    }

    fn define_views(schema: &mut Schematic) -> Result<(), bonsaidb::core::Error> {
        schema.define_view(NonRevokedPublicSigningKeys)?;
        schema.define_view(NonRevokedPublicEncryptionKeys)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub enum EncryptedKeyMethod {
    /// The encrypted key is stored such that the private key derived through a
    /// OPAQUE-KE login session can decrypt the key.
    OpaqueKe,
    /// The encrypted key is stored encrypted using the PublicKey such that the
    /// private backup key can decrypt the encrypted key. This mechanism is
    /// meant to be used for a physical backup, such as printing a piece of
    /// paper and storing it in a secure location.
    BackupKey(PublicKey),
}

#[derive(Debug)]
pub struct NonRevokedPublicSigningKeys;

impl View for NonRevokedPublicSigningKeys {
    type Collection = IdentityKey;
    type Key = Vec<u8>;
    type Value = ();

    fn unique(&self) -> bool {
        true
    }

    fn version(&self) -> u64 {
        0
    }

    fn name(&self) -> Result<bonsaidb::core::schema::Name, InvalidNameError> {
        Name::new("public-signing-keys")
    }

    fn map(&self, document: &Document<'_>) -> MapResult<Self::Key, Self::Value> {
        let key = document.contents::<IdentityKey>()?;
        if key.revoked_at.is_some() {
            Ok(None)
        } else {
            Ok(key
                .public_signing_key
                .map(|key| document.emit_key(key.to_bytes())))
        }
    }
}

#[derive(Debug)]
pub struct NonRevokedPublicEncryptionKeys;

impl View for NonRevokedPublicEncryptionKeys {
    type Collection = IdentityKey;
    type Key = Vec<u8>;
    type Value = ();

    fn unique(&self) -> bool {
        true
    }

    fn version(&self) -> u64 {
        0
    }

    fn name(&self) -> Result<bonsaidb::core::schema::Name, InvalidNameError> {
        Name::new("public-encryption-keys")
    }

    fn map(&self, document: &Document<'_>) -> MapResult<Self::Key, Self::Value> {
        let key = document.contents::<IdentityKey>()?;
        if key.revoked_at.is_some() {
            Ok(None)
        } else {
            Ok(key
                .public_encryption_key
                .map(|key| document.emit_key(key.to_bytes())))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisteredNotarization {
    pub identity_id: u64,
    pub identity_key_id: u64,
    pub attestation: Attestation,
}

impl Collection for RegisteredNotarization {
    fn collection_name() -> Result<CollectionName, InvalidNameError> {
        CollectionName::new(NCOG_AUTHORITY, "notarizations")
    }

    fn define_views(_schema: &mut Schematic) -> Result<(), bonsaidb::core::Error> {
        Ok(())
    }
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
    ChangePassword {
        password_request: RegistrationRequest,
    },
    #[actionable(protection = "none")]
    FinishPasswordRegistration {
        password_finalization: RegistrationFinalization,
    },
    #[actionable(protection = "none")]
    RegisterKey {
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

impl RequestDispatcher for Ncog {
    type Output = Response;
    type Error = anyhow::Error;
}

#[async_trait]
impl RegisterKeyHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
        expires_at: Option<OffsetDateTime>,
        encrypted_keys: Option<HashMap<EncryptedKeyMethod, Vec<u8>>>,
        public_signing_key: Option<PublicKey>,
        public_encryption_key: Option<PublicKey>,
    ) -> Result<Response, anyhow::Error> {
        if let Some(user_id) = self.client.user_id().await {
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

#[async_trait]
impl RegisterAccountHandler for Ncog {
    async fn handle(
        &self,
        _permissions: &Permissions,
        handle: String,
        password_request: RegistrationRequest,
    ) -> Result<Response, anyhow::Error> {
        todo!()
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
        password_response: RegistrationFinalization,
    ) -> Result<Response, anyhow::Error> {
        todo!()
    }
}
