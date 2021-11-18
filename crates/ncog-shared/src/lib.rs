use std::collections::HashMap;

use actionable::Actionable;
use bonsaidb::core::{
    custodian_password::{RegistrationFinalization, RegistrationRequest, RegistrationResponse},
    custom_api::CustomApi,
};
use ncog_encryption::PublicKey;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::schema::IdentityKey;

pub mod schema;

#[derive(Debug)]
pub struct NcogApi;

impl CustomApi for NcogApi {
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

// impl From<Error> for KeyserverError {
//     fn from(err: Error) -> Self {
//         Self::Encryption(err.to_string())
//     }
// }

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
