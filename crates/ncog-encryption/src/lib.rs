#![forbid(unsafe_code)]
#![warn(
    // TODO clippy::cargo,
    // TODO missing_docs,
    // clippy::missing_docs_in_private_items,
    clippy::pedantic,
    future_incompatible,
    rust_2018_idioms,
)]
#![allow(
    clippy::missing_errors_doc, // TODO clippy::missing_errors_doc
    clippy::missing_panics_doc, // TODO clippy::missing_panics_doc
    clippy::option_if_let_else,
    clippy::module_name_repetitions,
)]

use std::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
    hash::Hash,
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

use bonsaidb::core::schema::view::EnumKey;
use chrono::{DateTime, Utc};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer, Verifier};
use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    generic_array::sequence::Split,
    kdf::HkdfSha384,
    kem::X25519HkdfSha256,
    kex::{KeyExchange, X25519},
    Deserializable, EncappedKey, HpkeError, OpModeR, OpModeS, Serializable,
};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use pem::{Pem, PemError};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use yasna::{ASN1Error, ASN1ErrorKind};

pub struct PublishedKey {
    pub user: u64,
    pub key: PublicKey,
    pub published: DateTime<Utc>,
    pub revoked: Option<DateTime<Utc>>,
    pub expires: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicIdentityKey {
    pub key: PublicKey,
    pub domain: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentifiedSignature {
    pub signed_by: PublicIdentityKey,
    pub signature: Signature,
}

impl IdentifiedSignature {
    pub fn verify(&self, payload: &[u8]) -> Result<(), Error> {
        self.signed_by.key.verify(&self.signature, payload)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Signature {
    Ed25519(ed25519_dalek::Signature),
}

impl Signature {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Signature::Ed25519(signature) => signature.to_bytes().to_vec(),
        }
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        match self {
            Signature::Ed25519(signature) => pem::encode(&Pem {
                tag: String::from("ED25519 SIGNATURE"),
                contents: signature.to_bytes().to_vec(),
            }),
        }
    }

    pub fn from_pem(signature: &[u8]) -> Result<Self, Error> {
        let signature = pem::parse(&signature)?;
        if signature.tag == "ED25519 SIGNATURE" {
            let signature: [u8; 64] = signature
                .contents
                .try_into()
                .map_err(|_| Error::Message(String::from("signature length is incorrect")))?;
            let signature = ed25519_dalek::Signature::from_bytes(&signature)?;
            Ok(Self::Ed25519(signature))
        } else {
            Err(Error::IncorrectKeyType)
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PublicKey {
    Ed25519(ed25519_dalek::PublicKey),
    X25519(<hpke::kex::X25519 as KeyExchange>::PublicKey),
}

#[derive(
    Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, FromPrimitive, ToPrimitive,
)]
pub enum PublicKeyKind {
    Ed25519 = 1,
    X25519 = 2,
}

impl EnumKey for PublicKeyKind {}

#[derive(thiserror::Error, Debug)]
#[error("unsupported public key kind")]
pub struct UnsupportedPublicKeyKind;

impl TryFrom<u64> for PublicKeyKind {
    type Error = UnsupportedPublicKeyKind;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::from_u64(value).ok_or(UnsupportedPublicKeyKind)
    }
}

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ed25519(l0), Self::Ed25519(r0)) => l0 == r0,
            (Self::X25519(l0), Self::X25519(r0)) => l0.to_bytes() == r0.to_bytes(),
            _ => false,
        }
    }
}

impl Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            PublicKey::Ed25519(key) => key.to_bytes().hash(state),
            PublicKey::X25519(key) => key.to_bytes().hash(state),
        }
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519(arg0) => f.debug_tuple("ED25519").field(arg0).finish(),
            Self::X25519(arg0) => f.debug_tuple("X25519").field(&arg0.to_bytes()).finish(),
        }
    }
}

impl PublicKey {
    pub fn from_kind_and_bytes(kind: &PublicKeyKind, bytes: &[u8]) -> Result<Self, Error> {
        match kind {
            PublicKeyKind::Ed25519 => {
                let public_key = ed25519_dalek::PublicKey::from_bytes(bytes)?;
                Ok(Self::Ed25519(public_key))
            }
            PublicKeyKind::X25519 => Ok(Self::X25519(
                <X25519 as KeyExchange>::PublicKey::from_bytes(bytes)?,
            )),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> PublicKeyKind {
        match self {
            PublicKey::Ed25519(_) => PublicKeyKind::Ed25519,
            PublicKey::X25519(_) => PublicKeyKind::X25519,
        }
    }

    pub fn encrypt_for(
        &self,
        mut payload: Vec<u8>,
        subject: Vec<u8>,
        additional_data: Vec<u8>,
        sender: Option<&SecretKey>,
    ) -> Result<EncryptedPayload, Error> {
        match self {
            PublicKey::X25519(public_key) => {
                let mut csprng = OsRng::default();
                let op_mode = if let Some(sender) = sender {
                    match sender {
                        SecretKey::ED25519(_) => {
                            let keypair = sender.x25519_keypair();

                            OpModeS::Auth(keypair)
                        }
                    }
                } else {
                    OpModeS::Base
                };
                let (encapsulated_key, mut context) =
                    hpke::setup_sender::<ChaCha20Poly1305, HkdfSha384, X25519HkdfSha256, _>(
                        &op_mode,
                        public_key,
                        &subject,
                        &mut csprng,
                    )?;
                let tag = context.seal(&mut payload, &additional_data)?;
                Ok(EncryptedPayload {
                    subject,
                    encapsulated_key: encapsulated_key.to_bytes().to_vec(),
                    tag: tag.to_bytes().to_vec(),
                    additional_data,
                    ciphertext: payload,
                    sender: sender.map(SecretKey::public_encryption_key),
                })
            }
            _ => Err(Error::IncorrectKeyType),
        }
    }

    pub fn verify(&self, signature: &Signature, payload: &[u8]) -> Result<(), Error> {
        match (self, signature) {
            (PublicKey::Ed25519(public_key), Signature::Ed25519(signature)) => {
                public_key.verify(payload, signature).map_err(Error::from)
            }
            _ => Err(Error::IncorrectKeyType),
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::Ed25519(key) => key.to_bytes().to_vec(),
            PublicKey::X25519(key) => key.to_bytes().to_vec(),
        }
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        match self {
            PublicKey::Ed25519(public_key) => pem::encode(&Pem {
                tag: String::from("ED25519 PUBLIC KEY"),
                contents: public_key.to_bytes().to_vec(),
            }),
            PublicKey::X25519(public_key) => pem::encode(&Pem {
                tag: String::from("X25519 PUBLIC KEY"),
                contents: public_key.to_bytes().to_vec(),
            }),
        }
    }

    pub fn from_pem(public_key: &[u8]) -> Result<Self, Error> {
        let pem = pem::parse(&public_key)?;
        if pem.tag == "ED25519 PUBLIC KEY" {
            Self::from_kind_and_bytes(&PublicKeyKind::Ed25519, &pem.contents)
        } else if pem.tag == "X25519 PUBLIC KEY" {
            Self::from_kind_and_bytes(&PublicKeyKind::X25519, &pem.contents)
        } else {
            Err(Error::IncorrectKeyType)
        }
    }
}

#[non_exhaustive]
pub enum SecretKey {
    ED25519(ed25519_dalek::Keypair),
}

impl SecretKey {
    #[must_use]
    pub fn random() -> Self {
        let mut csprng = rand_07::rngs::OsRng::default();
        Self::ED25519(ed25519_dalek::Keypair::generate(&mut csprng))
    }

    #[must_use]
    pub fn public_encryption_key(&self) -> PublicKey {
        match self {
            SecretKey::ED25519(_) => PublicKey::X25519(self.x25519_public_key()),
        }
    }

    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn public_signing_key(&self) -> PublicKey {
        match self {
            SecretKey::ED25519(key) => PublicKey::Ed25519(key.public),
        }
    }

    pub fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, Error> {
        match self {
            SecretKey::ED25519(_) => {
                let encapped_key = EncappedKey::from_bytes(&payload.encapsulated_key)?;
                let op_mode = if let Some(sender) = &payload.sender {
                    OpModeR::Auth(match sender {
                        PublicKey::X25519(public_key) => public_key.clone(),
                        _ => return Err(Error::IncorrectKeyType),
                    })
                } else {
                    OpModeR::Base
                };
                let recipient_secret_key = self.x25519_secret_key();
                let mut context =
                    hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha384, X25519HkdfSha256>(
                        &op_mode,
                        &recipient_secret_key,
                        &encapped_key,
                        &payload.subject,
                    )?;
                let mut output = payload.ciphertext.clone();
                let tag = AeadTag::from_bytes(&payload.tag)?;
                context.open(&mut output, &payload.additional_data, &tag)?;
                Ok(output)
            }
        }
    }

    #[must_use]
    pub fn to_pem(&self) -> String {
        match self {
            SecretKey::ED25519(keypair) => pem::encode(&Pem {
                tag: String::from("ED25519 PRIVATE KEY"),
                contents: keypair.secret.to_bytes().to_vec(),
            }),
        }
    }

    pub fn from_pem(secret_key: &[u8]) -> Result<Self, Error> {
        let secret_key = pem::parse(&secret_key)?;
        if secret_key.tag == "ED25519 PRIVATE KEY" {
            let secret = ed25519_dalek::SecretKey::from_bytes(&secret_key.contents)?;
            Ok(Self::ED25519(ed25519_dalek::Keypair {
                public: ed25519_dalek::PublicKey::from(&secret),
                secret,
            }))
        } else {
            Err(Error::IncorrectKeyType)
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        match self {
            SecretKey::ED25519(secret_key) => {
                let signature = secret_key.sign(message);
                Ok(Signature::Ed25519(signature))
            }
        }
    }

    fn x25519_public_key(&self) -> <X25519 as KeyExchange>::PublicKey {
        match self {
            SecretKey::ED25519(key) => <X25519 as KeyExchange>::PublicKey::from_bytes(
                &CompressedEdwardsY(*key.public.as_bytes())
                    .decompress()
                    .unwrap()
                    .to_montgomery()
                    .to_bytes(),
            )
            .unwrap(),
        }
    }

    fn x25519_secret_key(&self) -> <X25519 as KeyExchange>::PrivateKey {
        match self {
            SecretKey::ED25519(keypair) => <X25519 as KeyExchange>::PrivateKey::from_bytes(&{
                let h = Sha512::digest(keypair.secret.as_bytes());
                let h = Split::split(h).0;
                <[u8; 32]>::from(h)
            })
            .unwrap(),
        }
    }

    fn x25519_keypair(
        &self,
    ) -> (
        <X25519 as KeyExchange>::PrivateKey,
        <X25519 as KeyExchange>::PublicKey,
    ) {
        match self {
            SecretKey::ED25519(_) => (self.x25519_secret_key(), self.x25519_public_key()),
        }
    }
}

pub struct SecretIdentityKey {
    pub key: SecretKey,
    pub domain: String,
}

impl SecretIdentityKey {
    pub fn encrypt(
        &self,
        payload: Vec<u8>,
        subject: Vec<u8>,
        additional_data: Vec<u8>,
        recipient: &PublicKey,
    ) -> Result<EncryptedPayload, Error> {
        recipient.encrypt_for(payload, subject, additional_data, Some(&self.key))
    }

    pub fn sign(&self, message: &[u8]) -> Result<IdentifiedSignature, Error> {
        let signature = self.key.sign(message)?;
        Ok(IdentifiedSignature {
            signed_by: PublicIdentityKey {
                key: self.key.public_signing_key(),
                domain: self.domain.clone(),
            },
            signature,
        })
    }

    pub fn notarize(
        &self,
        id: u64,
        signer_timestamp: u64,
        signatures: Vec<IdentifiedSignature>,
    ) -> Result<Notarization, Error> {
        let notary_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock set in past")
            .as_secs();
        let attestation = Attestation {
            notary_timestamp,
            signer_timestamp,
            signatures,
        };

        let notarization_payload = Notarization::format_payload(id, &attestation);

        let notarization = self.sign(&notarization_payload)?;

        Ok(Notarization {
            notarization,
            id,
            attestation,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub subject: Vec<u8>,
    pub encapsulated_key: Vec<u8>,
    pub tag: Vec<u8>,
    pub additional_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub sender: Option<PublicKey>,
}

impl EncryptedPayload {
    // TODO This should probably be a better format than bincode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_bytes(&self.subject);
                writer.next().write_bytes(&self.encapsulated_key);
                writer.next().write_bytes(&self.tag);
                writer.next().write_bytes(&self.additional_data);
                writer.next().write_bytes(&self.ciphertext);
                if let Some(sender) = &self.sender {
                    writer.next().write_enum(sender.kind() as i64);
                    writer.next().write_bytes(&sender.to_bytes());
                } else {
                    writer.next().write_enum(-1);
                }
            });
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut our_error = None;
        yasna::parse_der(bytes, |reader| {
            reader.read_sequence(|reader| {
                let subject = reader.next().read_bytes()?;
                let encapsulated_key = reader.next().read_bytes()?;
                let tag = reader.next().read_bytes()?;
                let additional_data = reader.next().read_bytes()?;
                let ciphertext = reader.next().read_bytes()?;
                let sender_key_kind = reader.next().read_enum()?;
                let sender = if let Ok(sender_key_kind) = u64::try_from(sender_key_kind) {
                    let sender_key_kind =
                        PublicKeyKind::try_from(sender_key_kind).map_err(|err| {
                            our_error = Some(Error::from(err));
                            ASN1Error::new(ASN1ErrorKind::Invalid)
                        })?;
                    let sender_key = reader.next().read_bytes()?;
                    Some(
                        PublicKey::from_kind_and_bytes(&sender_key_kind, &sender_key).map_err(
                            |err| {
                                our_error = Some(err);
                                ASN1Error::new(ASN1ErrorKind::Invalid)
                            },
                        )?,
                    )
                } else {
                    None
                };

                Ok(Self {
                    subject,
                    encapsulated_key,
                    tag,
                    additional_data,
                    ciphertext,
                    sender,
                })
            })
        })
        .map_err(|err| {
            // yasna doesn't let us bubble up our own error type. If we
            // generated a more descriptive error, we will return it here
            // instead of the yasna error.
            if let Some(err) = our_error {
                err
            } else {
                Error::from(err)
            }
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("hpke error: {0}")]
    HPKE(#[from] HpkeError),
    #[error("ED25519 error: {0}")]
    ED25519(#[from] ed25519_dalek::ed25519::Error),
    #[error("incorrect key type")]
    IncorrectKeyType,
    #[error("PEM file error: {0}")]
    Pem(#[from] PemError),
    #[error("PEM file error: {0}")]
    Asn(#[from] ASN1Error),
    #[error("unexpected error: {0}")]
    Message(String),
    #[error("unsupported public key kind")]
    UnsupportedPublicKeyKind,
}
impl From<UnsupportedPublicKeyKind> for Error {
    fn from(_: UnsupportedPublicKeyKind) -> Self {
        Self::UnsupportedPublicKeyKind
    }
}

/// A notarization provides a method for a third party to attest to a signature
/// taking place at a moment in time, without needing to see the payload being
/// signed.
///
/// There are three signatures that should be verified when validating the
/// notarization:
///
/// - The `notarization` verifies the contents of the notarization itself.
/// - The `signature` verifies that the signer signed the payload.
pub struct Notarization {
    /// The signature and public key produced by the notary. It is a signature
    /// produced from the concatenation of the raw bytes of the rest of the
    /// structure, in big-endian encoding.
    pub notarization: IdentifiedSignature,
    /// The unique ID of the notarization assigned by the notary.
    pub id: u64,
    /// The information the notary is attesting to.
    pub attestation: Attestation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Attestation {
    /// The time of the notarization as attested by the notary. Measured in
    /// seconds since January 1, 1970 00:00:00 UTC.
    pub notary_timestamp: u64,
    /// The time of the signatures as attested by the signer. Measured in
    /// seconds since January 1, 1970 00:00:00 UTC.
    pub signer_timestamp: u64,
    /// The signatures being notarized.
    pub signatures: Vec<IdentifiedSignature>,
}

impl Attestation {
    pub fn format_for_notarization<W: Write>(&self, notarization_payload: &mut W) {
        // Timestamps
        notarization_payload
            .write_all(&self.notary_timestamp.to_be_bytes())
            .unwrap();
        notarization_payload
            .write_all(&self.signer_timestamp.to_be_bytes())
            .unwrap();

        for signature in &self.signatures {
            // Signer identity
            notarization_payload
                .write_all(signature.signed_by.domain.as_bytes())
                .unwrap();
            notarization_payload
                .write_all(&signature.signed_by.key.to_bytes())
                .unwrap();

            // Signature
            notarization_payload
                .write_all(&signature.signature.to_bytes())
                .unwrap();
        }
    }
}

impl Notarization {
    pub fn verify(&self, payload: &[u8]) -> Result<(), Error> {
        for signature in &self.attestation.signatures {
            signature.verify(payload)?;
        }

        let notarization = Self::format_payload(self.id, &self.attestation);
        self.notarization.verify(&notarization)?;

        Ok(())
    }

    #[must_use]
    pub fn format_payload(notarization_id: u64, attestation: &Attestation) -> Vec<u8> {
        let mut notarization_payload = Vec::new();

        // Notarization ID
        notarization_payload
            .write_all(&notarization_id.to_be_bytes())
            .unwrap();

        attestation.format_for_notarization(&mut notarization_payload);

        notarization_payload
    }
}

#[test]
fn anonymous_sender_encrypt_test() {
    let bob = SecretKey::random();
    let bob_public_key = bob.public_encryption_key();

    let payload = bob_public_key
        .encrypt_for(
            b"payload".to_vec(),
            b"my subject".to_vec(),
            b"additional data".to_vec(),
            None,
        )
        .unwrap();

    // Decrypt the payload
    let decrypted = bob.decrypt(&payload).unwrap();
    assert_eq!(decrypted, b"payload");
}

#[test]
fn verified_sender_encrypt_test() {
    let alice = SecretIdentityKey {
        key: SecretKey::random(),
        domain: String::from("acme"),
    };

    let bob = SecretKey::random();
    let bob_public_key = bob.public_encryption_key();

    let mut payload = alice
        .encrypt(
            b"payload".to_vec(),
            b"my subject".to_vec(),
            b"additional data".to_vec(),
            &bob_public_key,
        )
        .unwrap();

    // Decrypt the payload
    let decrypted = bob.decrypt(&payload).unwrap();
    assert_eq!(decrypted, b"payload");

    // Try decrypting without the public key
    payload.sender = None;
    assert!(bob.decrypt(&payload).is_err());
}

#[test]
fn notarization_test() {
    let payload = b"payload";

    let alice = SecretIdentityKey {
        key: SecretKey::random(),
        domain: String::from("acme"),
    };

    let bob = SecretIdentityKey {
        key: SecretKey::random(),
        domain: String::from("acme"),
    };

    let alice_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock set in past")
        .as_secs();
    let signature = alice.sign(payload).unwrap();
    let notarization_id = 1; // Bob would generate this
    let notarization = bob
        .notarize(notarization_id, alice_timestamp, vec![signature])
        .unwrap();
    notarization.verify(payload).unwrap();
}
