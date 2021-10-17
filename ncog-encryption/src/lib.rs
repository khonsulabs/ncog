use std::{
    fmt::Debug,
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, Verifier};
use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha384,
    kem::X25519HkdfSha256,
    kex::KeyExchange,
    Deserializable, EncappedKey, HpkeError, Kem, OpModeR, OpModeS, Serializable,
};
use rand::rngs::OsRng;

pub struct PublishedKey {
    pub user: u64,
    pub key: PublicKey,
    pub published: DateTime<Utc>,
    pub revoked: Option<DateTime<Utc>>,
    pub expires: DateTime<Utc>,
}

#[derive(Debug)]
pub struct PublicIdentityKey {
    pub key: PublicKey,
    pub domain: String,
}

#[derive(Debug)]
pub struct IdentifiedSignature {
    pub signed_by: PublicIdentityKey,
    pub signature: Signature,
}

impl IdentifiedSignature {
    pub fn verify(&self, payload: &[u8]) -> Result<(), Error> {
        self.signed_by.key.verify(&self.signature, payload)
    }
}

#[derive(Debug)]
pub enum Signature {
    Ed25519(ed25519_dalek::Signature),
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Signature::Ed25519(signature) => signature.to_bytes().to_vec(),
        }
    }
}

pub enum PublicKey {
    ED25519(ed25519_dalek::PublicKey),
    X25519(<hpke::kex::X25519 as KeyExchange>::PublicKey),
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ED25519(arg0) => f.debug_tuple("ED25519").field(arg0).finish(),
            Self::X25519(arg0) => f.debug_tuple("X25519").field(&arg0.to_bytes()).finish(),
        }
    }
}

impl PublicKey {
    pub fn encrypt_for(
        &self,
        mut payload: Vec<u8>,
        subject: Vec<u8>,
        additional_data: Vec<u8>,
        sender: Option<&PrivateKey>,
    ) -> Result<EncryptedPayload, Error> {
        match self {
            PublicKey::X25519(public_key) => {
                let mut csprng = OsRng::default();
                let op_mode = if let Some(sender) = sender {
                    match sender {
                        PrivateKey::X25519(auth) => OpModeS::Auth(auth.clone()),
                        _ => return Err(Error::IncorrectKeyType),
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
                    sender: sender.map(|sender| sender.public_key()),
                })
            }
            _ => Err(Error::IncorrectKeyType),
        }
    }

    pub fn verify(&self, signature: &Signature, payload: &[u8]) -> Result<(), Error> {
        match (self, signature) {
            (PublicKey::ED25519(public_key), Signature::Ed25519(signature)) => {
                public_key.verify(payload, signature).map_err(Error::from)
            }
            _ => Err(Error::IncorrectKeyType),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::ED25519(key) => key.to_bytes().to_vec(),
            PublicKey::X25519(key) => key.to_bytes().to_vec(),
        }
    }
}

pub enum PrivateKey {
    ED25519(ed25519_dalek::Keypair),
    X25519(
        (
            <hpke::kex::X25519 as KeyExchange>::PrivateKey,
            <hpke::kex::X25519 as KeyExchange>::PublicKey,
        ),
    ),
}

impl PrivateKey {
    pub fn new_signing() -> Self {
        let mut csprng = rand_07::rngs::OsRng::default();
        Self::ED25519(ed25519_dalek::Keypair::generate(&mut csprng))
    }

    pub fn new_encryption() -> Self {
        let mut csprng = OsRng::default();
        Self::X25519(<hpke::kem::X25519HkdfSha256 as Kem>::gen_keypair(
            &mut csprng,
        ))
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::ED25519(key) => PublicKey::ED25519(key.public),
            PrivateKey::X25519((_, public)) => PublicKey::X25519(public.clone()),
        }
    }

    pub fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, Error> {
        match self {
            PrivateKey::X25519((private_key, _)) => {
                let encapped_key = EncappedKey::from_bytes(&payload.encapsulated_key)?;
                let op_mode = if let Some(sender) = &payload.sender {
                    OpModeR::Auth(match sender {
                        PublicKey::X25519(public_key) => public_key.clone(),
                        _ => return Err(Error::IncorrectKeyType),
                    })
                } else {
                    OpModeR::Base
                };
                let mut context = hpke::setup_receiver::<
                    ChaCha20Poly1305,
                    HkdfSha384,
                    X25519HkdfSha256,
                >(
                    &op_mode, private_key, &encapped_key, &payload.subject
                )?;
                let mut output = payload.ciphertext.clone();
                let tag = AeadTag::from_bytes(&payload.tag)?;
                context.open(&mut output, &payload.additional_data, &tag)?;
                Ok(output)
            }
            _ => Err(Error::IncorrectKeyType),
        }
    }
}

pub struct PrivateIdentityKey {
    pub key: PrivateKey,
    pub domain: String,
}

impl PrivateIdentityKey {
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
        match &self.key {
            PrivateKey::ED25519(private_key) => {
                let signature = private_key.sign(message);
                Ok(IdentifiedSignature {
                    signed_by: PublicIdentityKey {
                        key: PublicKey::ED25519(private_key.public),
                        domain: self.domain.clone(),
                    },
                    signature: Signature::Ed25519(signature),
                })
            }
            _ => Err(Error::IncorrectKeyType),
        }
    }

    pub fn notarize(
        &self,
        signature: IdentifiedSignature,
        verification_data: Vec<u8>,
        verification_signature: Signature,
    ) -> Result<Notarization, Error> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock set in past")
            .as_secs();
        let signature_window = 0;

        let notarization_payload = Notarization::format_payload(
            timestamp,
            signature_window,
            &signature,
            &verification_data,
            &verification_signature,
        );

        let notarization = self.sign(&notarization_payload)?;

        Ok(Notarization {
            notarization,
            timestamp,
            signature_window,
            signature,
            verification_data,
            verification_signature,
        })
    }
}

#[derive(Debug)]
pub struct EncryptedPayload {
    pub subject: Vec<u8>,
    pub encapsulated_key: Vec<u8>,
    pub tag: Vec<u8>,
    pub additional_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub sender: Option<PublicKey>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("hpke error: {0}")]
    HPKE(#[from] HpkeError),
    #[error("ED25519 error: {0}")]
    ED25519(#[from] ed25519_dalek::ed25519::Error),
    #[error("incorrect key type")]
    IncorrectKeyType,
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
/// - The `verification_signature` verifies that the payload of the signature is
///   the orignal payload, and that the signer did not produce multiple payloads
///   with the same signature. The notary generates the `verification_data`
///   after it receives `signature`, preventing the signer from being able to
///   forge payloads.
pub struct Notarization {
    /// The signature and public key produced by the notary. It is a signature
    /// produced from the concatenation of the raw bytes of the rest of the
    /// structure, in big-endian encoding.
    pub notarization: IdentifiedSignature,
    /// The time of the notarization as attested by the notary. Measured in
    /// seconds since January 1, 1970 00:00:00 UTC.
    pub timestamp: u64,
    /// The number of seconds that the notarization process took.
    pub signature_window: u16,
    /// The signature being notarized.
    pub signature: IdentifiedSignature,
    /// Randomly generated data used to verify the payload being signed is
    /// uniquely the payload being signed.
    pub verification_data: Vec<u8>,
    /// A second signature created by signing the original payload concatenated
    /// by the `verification_data`. This signature must be created by the same
    /// keypair that generated the original `signature`.
    pub verification_signature: Signature,
}

impl Notarization {
    pub fn verify(&self, payload: &[u8]) -> Result<(), Error> {
        self.signature.verify(payload)?;

        let mut verification_payload =
            Vec::with_capacity(payload.len() + self.verification_data.len());
        verification_payload.extend(payload);
        verification_payload.extend(self.verification_data.iter());

        self.signature
            .signed_by
            .key
            .verify(&self.verification_signature, &verification_payload)?;

        Ok(())
    }

    pub fn format_payload(
        timestamp: u64,
        signature_window: u16,
        signature: &IdentifiedSignature,
        verification_data: &[u8],
        verification_signature: &Signature,
    ) -> Vec<u8> {
        let mut notarization_payload = Vec::new();

        // Timestamps
        notarization_payload
            .write_all(&timestamp.to_be_bytes())
            .unwrap();
        notarization_payload
            .write_all(&signature_window.to_be_bytes())
            .unwrap();

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

        // Verification data
        notarization_payload.write_all(verification_data).unwrap();

        // Verification signature
        notarization_payload
            .write_all(&verification_signature.to_bytes())
            .unwrap();

        notarization_payload
    }
}

#[test]
fn anonymous_sender_encrypt_test() {
    let bob = PrivateKey::new_encryption();
    let bob_public_key = bob.public_key();

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
    let alice = PrivateIdentityKey {
        key: PrivateKey::new_encryption(),
        domain: String::from("acme"),
    };

    let bob = PrivateKey::new_encryption();
    let bob_public_key = bob.public_key();

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

    let alice = PrivateIdentityKey {
        key: PrivateKey::new_signing(),
        domain: String::from("acme"),
    };

    let bob = PrivateIdentityKey {
        key: PrivateKey::new_signing(),
        domain: String::from("acme"),
    };

    let signature = alice.sign(payload).unwrap();
    // Normally this data would come from bob, randomly generated, after he received the signature.
    let verification_data = b"verification";
    let mut verification_payload = Vec::new();
    verification_payload.extend(payload);
    verification_payload.extend(verification_data);
    let verification_signature = alice.sign(&verification_payload).unwrap();

    let notarization = bob
        .notarize(
            signature,
            verification_data.to_vec(),
            verification_signature.signature,
        )
        .unwrap();
    notarization.verify(payload).unwrap();
}
