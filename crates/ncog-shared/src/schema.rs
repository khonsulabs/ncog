use std::collections::HashMap;

use bonsaidb::{
    core::{
        admin::password_config::PasswordConfig,
        connection::Connection,
        document::Document,
        schema::{
            Collection, CollectionDocument, CollectionName, InsertError, InvalidNameError,
            MapResult, Name, NamedCollection, Schema, SchemaName, Schematic, View,
        },
    },
    server::BackendError,
};
use ncog_encryption::{Attestation, PublicKey, PublicKeyKind};
use rand::Rng;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{EncryptedKeyMethod, KeyserverError, RedemptionLimit, TrustLevel};

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
        schema.define_collection::<Invitation>()?;
        Ok(())
    }
}

pub const NCOG_AUTHORITY: &str = "ncog";

#[derive(Debug, Serialize, Deserialize)]
pub struct Identity {
    pub user_id: Option<u64>,
    pub accepted_invitation_id: Option<u64>,
    pub handle: String,
    pub backup_keys: Vec<BackupKey>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupKey {
    pub label: String,
    pub created_at: OffsetDateTime,
    pub public_key: PublicKey,
}

impl Identity {
    pub async fn load_for_user_id<DB: Connection>(
        handle: &str,
        user_id: u64,
        db: &DB,
    ) -> Result<CollectionDocument<Self>, BackendError<KeyserverError>> {
        let identity = Self::load(handle, db)
            .await?
            .ok_or(BackendError::Backend(KeyserverError::UnknownIdentity))?;
        if identity.contents.user_id != Some(user_id) {
            return Err(BackendError::Backend(KeyserverError::UnknownIdentity));
        }
        Ok(identity)
    }
}

impl Collection for Identity {
    fn collection_name() -> Result<CollectionName, InvalidNameError> {
        CollectionName::new(NCOG_AUTHORITY, "identities")
    }

    fn define_views(schema: &mut Schematic) -> Result<(), bonsaidb::core::Error> {
        schema.define_view(IdentityByHandle)
    }
}

impl NamedCollection for Identity {
    type ByNameView = IdentityByHandle;
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
        Ok(vec![document.emit_key(identity.handle)])
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
    /// Optionally stored encrypted versions of the secret key.
    pub encrypted_secret_keys: Option<HashMap<EncryptedKeyMethod, Vec<u8>>>,
    /// The registered public keys.
    pub public_keys: HashMap<PublicKeyKind, PublicKey>,
}

impl Collection for IdentityKey {
    fn collection_name() -> Result<CollectionName, InvalidNameError> {
        CollectionName::new(NCOG_AUTHORITY, "identity-keys")
    }

    fn define_views(schema: &mut Schematic) -> Result<(), bonsaidb::core::Error> {
        schema.define_view(NonRevokedPublicKeys)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct NonRevokedPublicKeys;

impl View for NonRevokedPublicKeys {
    type Collection = IdentityKey;
    type Key = (PublicKeyKind, Vec<u8>);
    type Value = ();

    fn unique(&self) -> bool {
        true
    }

    fn version(&self) -> u64 {
        1
    }

    fn name(&self) -> Result<bonsaidb::core::schema::Name, InvalidNameError> {
        Name::new("public-signing-keys")
    }

    fn map(&self, document: &Document<'_>) -> MapResult<Self::Key, Self::Value> {
        let key = document.contents::<IdentityKey>()?;
        if key.revoked_at.is_some() {
            Ok(Vec::new())
        } else {
            Ok(key
                .public_keys
                .iter()
                .map(|(kind, key)| document.emit_key((*kind, key.to_bytes())))
                .collect())
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Invitation {
    pub created_by: u64,
    pub token: u64,
    pub trust_level: TrustLevel,
    pub expires_at: Option<OffsetDateTime>,
    pub max_redemptions: Option<RedemptionLimit>,
}

impl Collection for Invitation {
    fn collection_name() -> Result<CollectionName, InvalidNameError> {
        CollectionName::new(NCOG_AUTHORITY, "invitations")
    }

    fn define_views(schema: &mut Schematic) -> Result<(), bonsaidb::core::Error> {
        schema.define_view(InvitationByToken)?;
        Ok(())
    }
}

impl Invitation {
    pub async fn generate_random_token<C: Connection>(
        mut self,
        db: &C,
    ) -> Result<CollectionDocument<Self>, bonsaidb::core::Error> {
        loop {
            self.token = {
                let mut rng = rand::thread_rng();
                rng.gen_range(0..2_u64.pow(52))
            };

            self = match self.insert_into(db).await {
                Ok(doc) => return Ok(doc),
                Err(InsertError {
                    contents,
                    error: bonsaidb::core::Error::UniqueKeyViolation { .. },
                }) => contents,
                Err(InsertError { error, .. }) => return Err(error),
            }
        }
    }

    pub async fn load_from_token<C: Connection>(
        token: u64,
        db: &C,
    ) -> Result<CollectionDocument<Self>, BackendError<KeyserverError>> {
        if let Some(mapping) = db
            .view::<InvitationByToken>()
            .with_key(token)
            .query_with_docs()
            .await?
            .into_iter()
            .next()
        {
            Ok(CollectionDocument::try_from(mapping.document)?)
        } else {
            Err(BackendError::Backend(KeyserverError::UnknownInvitation))
        }
    }
}

#[derive(Debug)]
pub struct InvitationByToken;

impl View for InvitationByToken {
    type Collection = Invitation;
    type Key = u64;
    type Value = ();

    fn unique(&self) -> bool {
        true
    }

    fn version(&self) -> u64 {
        0
    }

    fn name(&self) -> Result<bonsaidb::core::schema::Name, InvalidNameError> {
        Name::new("by-token")
    }

    fn map(&self, document: &Document<'_>) -> MapResult<Self::Key, Self::Value> {
        let invitation = document.contents::<Invitation>()?;
        Ok(vec![document.emit_key(invitation.token)])
    }
}
