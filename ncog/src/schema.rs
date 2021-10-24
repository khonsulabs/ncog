use std::{borrow::Cow, collections::HashMap, convert::Infallible};

use bonsaidb::core::{
    admin::password_config::PasswordConfig,
    document::Document,
    schema::{
        Collection, CollectionName, InvalidNameError, Key, MapResult, Name, NamedCollection,
        Schema, SchemaName, Schematic, View,
    },
};
use ncog_encryption::{Attestation, Error, PublicKey, PublicKeyKind};
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
pub struct NonRevokedPublicKeys;

impl View for NonRevokedPublicKeys {
    type Collection = IdentityKey;
    type Key = EncodedPublicKey;
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
            Ok(Vec::new())
        } else {
            Ok(key
                .public_keys
                .iter()
                .map(|(kind, key)| document.emit_key(EncodedPublicKey::new(*kind, key)))
                .collect())
        }
    }
}

#[derive(Clone, Debug)]
pub struct EncodedPublicKey(Vec<u8>);

impl Key for EncodedPublicKey {
    type Error = Infallible;

    fn as_big_endian_bytes(&self) -> Result<std::borrow::Cow<'_, [u8]>, Infallible> {
        Ok(Cow::Borrowed(&self.0))
    }

    fn from_big_endian_bytes(bytes: &[u8]) -> Result<Self, Infallible> {
        Ok(Self(bytes.to_vec()))
    }
}

impl EncodedPublicKey {
    pub fn new(kind: PublicKeyKind, key: &PublicKey) -> Self {
        let mut view_key = key.to_bytes();
        view_key.splice(0..0, (kind as u8).to_be_bytes());
        Self(view_key)
    }
}

impl<'a> From<&'a PublicKey> for EncodedPublicKey {
    fn from(public_key: &'a PublicKey) -> Self {
        Self::new(public_key.kind(), public_key)
    }
}

impl TryFrom<EncodedPublicKey> for PublicKey {
    type Error = Error;
    fn try_from(encoded: EncodedPublicKey) -> Result<Self, Error> {
        let kind = PublicKeyKind::try_from(i64::from(encoded.0[0]))?;
        Self::from_kind_and_bytes(&kind, &encoded.0[1..])
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