use std::collections::HashMap;

use bonsaidb::core::{
    admin::password_config::PasswordConfig,
    document::Document,
    schema::{
        Collection, CollectionName, InvalidNameError, MapResult, Name, Schema, SchemaName,
        Schematic, View,
    },
};
use ncog_encryption::{Attestation, PublicKey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

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
    pub user_id: Option<u64>,
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
    /// Optionally stored encrypted versions of the secret key.
    pub encrypted_secret_keys: Option<HashMap<EncryptedKeyMethod, Vec<u8>>>,
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
    /// The encrypted key is stored such that the secret key derived through a
    /// OPAQUE-KE login session can decrypt the key.
    OpaqueKe,
    /// The encrypted key is stored encrypted using the PublicKey such that the
    /// secret backup key can decrypt the encrypted key. This mechanism is
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
