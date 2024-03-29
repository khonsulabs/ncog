# ncog

![ncog forbids unsafe code](https://img.shields.io/badge/unsafe-forbid-success)
![ncog is considered experimental and unsupported](https://img.shields.io/badge/status-experimental-blueviolet)
[![crate version](https://img.shields.io/crates/v/ncog.svg)](https://crates.io/crates/ncog)
[![Live Build Status](https://img.shields.io/github/workflow/status/khonsulabs/ncog/Tests/main)](https://github.com/khonsulabs/ncog/actions?query=workflow:Tests)
[![HTML Coverage Report for `main` branch](https://khonsulabs.github.io/ncog/coverage/badge.svg)](https://ncog.dev/coverage/)
[![Documentation for `main` branch](https://img.shields.io/badge/docs-main-informational)](https://ncog.dev/main/ncog/)

Ncog aims to be a self-hosted platform for privacy and data independence.

> **Warning:** Ncog is incredibly early in development. Ncog is built using cryptography, and none of its authors claim to be cryptographers. It has not been audited. Additionally, it relies on several cryptography libraries that
also have not been audited. As such, use this software at your own risk.
> 
> We welcome [all feedback, questions, and critiques](https://github.com/khonsulabs/ncog/issues/new).

## Goals

An Ncog installation allows one or more users to use the server's "domain" for authentication and any other services built atop the Ncog server.

For example, the Khonsu Labs' public instance will be hosted at the domain `ncog.id`. The project founder's ncog id will be `ecton@ncog.id`.

Ncog is a key server at heart. The key server acts as a registry of public keys, enabling users to query the validity of each others' public keys.

Optionally, the key server can also offer secret-key backups using strategies that keep secret keys secure. This also enables Ncog to seamlessly synchronize secret keys between devices without exposing the unencrypted secret key to the Ncog server.

On top of this core, we plan to build a suite of services that solve many day-to-day problems that many people face: communication, scheduling, and collaborating.

To accomplish these services, we aim to do it through public APIs that we hope will expand Ncog into a general purpose platform where many people create interesting services. Our vision is to ressurrect the feeling of the days of BBSes where individuals could run a server and host useful or intersting services for friends, neighbors, or family to use.

## Cryptography Utilized

Secret keys are randomly generated [Ed25519][ed25519-dalek] keys. The same secret key can be converted deterministically to an [X25519](https://github.com/dalek-cryptography/x25519-dalek) secret key.

For signatures, [`Ed25519`](https://en.wikipedia.org/wiki/EdDSA) is utilized through the [`ed25519-dalek`][ed25519-dalek] crate.

The [`curve25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek) crate is used to convert between key types.

For public-key encryption, [`HPKE`][hpke] is utilized through the [`hpke`](https://github.com/rozbb/rust-hpke) crate. Ncog currently utilizes `X25519-HKDF-SHA256` for the KEM, `HKDF-SHA384` for the KDF, and `ChaCha20Poly1305` for the AEAD.

### Why Ncog reuses the same secret key for signing and encryption

Our public-key encryption method, [`HPKE`][hpke], supports a form of encryption that also authenticates the sender to the recipient. To us, it seems a silly argument that authentication should be kept separate from encryption when the cryptography community have designed a standard that use the same key for both purposes.

When initially designing Ncog, we investigated this common suggestion and concluded that most arguments that we discovered were centered around key management issues which Ncog is aiming to solve. We haven't found any compelling argument in favor of keeping separate keys. If you believe you have a compelling argument that isn't solved by our approach to secret management, please [file an issue with details](https://github.com/khonsulabs/ncog/issues/new).

With all of that said, the APIs are designed to enable keeping your keys split if you desire to do so -- only publish one of the public keys when registering your key.

## Command Line Interface

### Server Management

Install a self-signed certificate:
```sh
ncog db <server-data-path> server certificate install-self-signed --server-name <hostname>
```

Launch the server:
```sh
ncog db <server-data-path> server serve
```

### Account Management

Register an account:
```sh
ncog <server-hostname> account register <username>
```

You will be prompted to enter your password twice for verification. The password is registered with the server using OPAQUE-KE, which provides a secure mechanism to verify your password without it ever leaving the machine you're entering it on.

### Key Management

#### Creating a secret key

```sh
ncog key new -o <path>
```

#### Exporting a secret key's public keys

Signing key:

```sh
ncog key export-public signing -i <secret-key-path> [-o <path>]
```

Encryption key:

```sh
ncog key export-public encryption -i <secret-key-path> [-o <path>]
```

### Encryption

#### Encrypting a file for a recipient anonymously

```sh
ncog key encrypt -p <recipient-public-key-path> -i <plaintext-path> -o <ciphertext-path>
```

#### Encrypting a file for a recipient such that the recipient can verify the sender

```sh
ncog key encrypt -p <recipient-public-key-path> -s <sender-secret-key-path> -i <plaintext-path> -o <ciphertext-path>
```

#### Decrypting an encrypted file

Regardless of whether the file was encrypted anonymously or not, it can be decrypted using the same command:

```sh
ncog key decrypt -p <secret-key-path> -i <ciphertext-path> -o <plaintext-path>
```

If the file wasn't sent anonymously, the sender's public key will be echoed to stdout before reporting success.

[hpke]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-hpke/
[ed25519-dalek]: https://github.com/dalek-cryptography/ed25519-dalek