use std::fmt::Debug;

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

#[derive(Debug)]
pub enum Signature {
    Ed25519(ed25519_dalek::Signature),
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
    ) -> Result<EncryptedPayload, Error> {
        match self {
            PublicKey::X25519(public_key) => {
                let mut csprng = OsRng::default();
                let (encapsulated_key, mut context) =
                    hpke::setup_sender::<ChaCha20Poly1305, HkdfSha384, X25519HkdfSha256, _>(
                        &OpModeS::Base,
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
                let mut context = hpke::setup_receiver::<
                    ChaCha20Poly1305,
                    HkdfSha384,
                    X25519HkdfSha256,
                >(
                    &OpModeR::Base, private_key, &encapped_key, &payload.subject
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
    pub fn sign_and_encrypt_for(
        &self,
        recipient: &PublicKey,
        payload: Vec<u8>,
        subject: Vec<u8>,
        additional_data: Vec<u8>,
    ) -> Result<SignedPayload, Error> {
        let payload = recipient.encrypt_for(payload, subject, additional_data)?;
        Ok(SignedPayload {
            signature: self.sign(&payload.ciphertext)?,
            payload,
        })
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
}

#[derive(Debug)]
pub struct EncryptedPayload {
    pub subject: Vec<u8>,
    pub encapsulated_key: Vec<u8>,
    pub tag: Vec<u8>,
    pub additional_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub struct SignedPayload {
    pub payload: EncryptedPayload,
    pub signature: IdentifiedSignature,
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

#[test]
fn sign_and_encrypt_test() {
    let alice_private_signing_key = PrivateIdentityKey {
        key: PrivateKey::new_signing(),
        domain: String::from("acme"),
    };
    let alice_public_signing_key = alice_private_signing_key.key.public_key();

    let bob = PrivateKey::new_encryption();
    let bob_public_key = bob.public_key();

    let payload = alice_private_signing_key
        .sign_and_encrypt_for(
            &bob_public_key,
            b"payload".to_vec(),
            b"my subject".to_vec(),
            b"additional data".to_vec(),
        )
        .unwrap();

    // Verify the signature
    alice_public_signing_key
        .verify(&payload.signature.signature, &payload.payload.ciphertext)
        .unwrap();

    // Decrypt the payload
    let decrypted = bob.decrypt(&payload.payload).unwrap();
    assert_eq!(decrypted, b"payload");
}
