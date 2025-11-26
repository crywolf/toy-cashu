use std::str::FromStr;

use anyhow::{Context, Result, bail};
use secp256k1::Secp256k1;
use secp256k1::hashes::Hash;
use secp256k1::hashes::sha256::Hash as Sha256Hash;
use secp256k1::rand::prelude::RngCore;
use secp256k1::{Parity, PublicKey as UncompressedPublicKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

/// Secret message: 32 random hex encoded bytes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret(String);

impl Secret {
    // Generates 32 random hex encoded bytes
    pub fn generate() -> Self {
        let mut rng = secp256k1::rand::rng();

        let mut random_bytes = [0u8; 32];

        rng.fill_bytes(&mut random_bytes);
        let secret = hex::encode(random_bytes);
        Self(secret)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// PublicKey
#[derive(PartialEq)]
pub struct PublicKey {
    inner: secp256k1::PublicKey,
}

impl From<secp256k1::PublicKey> for PublicKey {
    fn from(inner: secp256k1::PublicKey) -> Self {
        Self { inner }
    }
}

impl FromStr for PublicKey {
    type Err = anyhow::Error;

    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        Self::from_hex(hex)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl PublicKey {
    /// Parse from `hex` string
    pub fn from_hex<S>(hex: S) -> Result<Self>
    where
        S: AsRef<str>,
    {
        let hex: &str = hex.as_ref();

        // Check size
        if hex.len() != 33 * 2 {
            bail!(
                "Invalid public key size: expected 33, got {}",
                hex.len() / 2
            );
        }

        Ok(Self {
            inner: secp256k1::PublicKey::from_str(hex)?,
        })
    }

    pub fn to_hex(&self) -> String {
        self.inner.to_string()
    }

    /// Adds a second key to this one, returning the sum
    pub fn combine(&self, other: &Self) -> Result<Self> {
        Ok(self.inner.combine(&other.inner)?.into())
    }

    /// Tweaks a [`PublicKey`] by multiplying by tweak modulo the curve order
    pub fn mul_tweak(&self, other: &SecretKey) -> Result<Self> {
        let secp = Secp256k1::new();
        let other = secp256k1::Scalar::from(other.inner);

        Ok(self.inner.mul_tweak(&secp, &other)?.into())
    }

    /// Negates the public key
    pub fn negate(&self) -> Self {
        let secp = Secp256k1::new();

        self.inner.negate(&secp).into()
    }
}

/// SecretKey
#[derive(Clone)]
pub struct SecretKey {
    inner: secp256k1::SecretKey,
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret key")
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey(XXXX)")
    }
}

impl From<secp256k1::SecretKey> for SecretKey {
    fn from(inner: secp256k1::SecretKey) -> Self {
        Self { inner }
    }
}

impl SecretKey {
    /// Generates a new random secret key
    pub fn generate() -> Self {
        Self {
            inner: secp256k1::SecretKey::new(&mut secp256k1::rand::rng()),
        }
    }

    /// Parse from `hex` string
    pub fn from_hex<S>(hex: S) -> Result<Self>
    where
        S: AsRef<str>,
    {
        Ok(Self {
            inner: secp256k1::SecretKey::from_str(hex.as_ref())?,
        })
    }

    /// Returns the PublicKey for this SecretKey.
    pub fn public_key(&self) -> PublicKey {
        let secp = secp256k1::Secp256k1::new();
        self.inner.public_key(&secp).into()
    }

    /// Returns Schnorr signature of the `msg` according to NUT-20
    pub fn sign_mint_quote(&self, msg: &str) -> [u8; 64] {
        let msg_hash = Sha256Hash::hash(msg.as_bytes());

        let secp = Secp256k1::new();
        let keypair = self.inner.keypair(&secp);

        let signature = secp.sign_schnorr_no_aux_rand(msg_hash.as_byte_array(), &keypair);
        signature.to_byte_array()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.inner.non_secure_erase();
    }
}

/// Deterministically maps a message to a public key point on the secp256k1
/// curve, utilizing a domain separator to ensure uniqueness.
///
/// For definition in NUT see [NUT-00](https://github.com/cashubtc/nuts/blob/main/00.md)
pub fn hash_to_curve(message: &[u8]) -> Result<PublicKey> {
    const DOMAIN_SEPARATOR: &[u8; 28] = b"Secp256k1_HashToCurve_Cashu_";

    let msg_to_hash: Vec<u8> = [DOMAIN_SEPARATOR, message].concat();

    let msg_hash: [u8; 32] = Sha256Hash::hash(&msg_to_hash).to_byte_array();

    let mut counter: u32 = 0;
    while counter < 2_u32.pow(16) {
        let mut bytes_to_hash: Vec<u8> = Vec::with_capacity(36);
        bytes_to_hash.extend_from_slice(&msg_hash);
        bytes_to_hash.extend_from_slice(&counter.to_le_bytes());

        let hash: [u8; 32] = Sha256Hash::hash(&bytes_to_hash).to_byte_array();

        // Try to parse public key
        match XOnlyPublicKey::from_byte_array(hash) {
            Ok(pk) => {
                let pubkey = UncompressedPublicKey::from_x_only_public_key(pk, Parity::Even);
                return Ok(pubkey.into());
            }
            Err(_) => {
                counter += 1;
            }
        }
    }

    bail!("No valid point");
}

/// Generates deterministic SHA256 hash for a given input list of public keys for DLEQ proof validation.
///
/// For definition in NUT see [NUT-12](https://github.com/cashubtc/nuts/blob/main/12.md)
pub fn hash_e(r1: &str, r2: &str, k: &str, c_: &str) -> Result<String> {
    let r1 = hex::encode(
        PublicKey::from_hex(r1)
            .context("pubkey from 'r1'")?
            .inner
            .serialize_uncompressed(),
    );

    let r2 = hex::encode(
        PublicKey::from_hex(r2)
            .context("pubkey from 'r2'")?
            .inner
            .serialize_uncompressed(),
    );

    let k = hex::encode(
        PublicKey::from_hex(k)
            .context("pubkey from 'k'")?
            .inner
            .serialize_uncompressed(),
    );

    let c_ = hex::encode(
        PublicKey::from_hex(c_)
            .context("pubkey from 'c_'")?
            .inner
            .serialize_uncompressed(),
    );

    let data = [r1, r2, k, c_].concat();

    let hash = Sha256Hash::hash(data.as_bytes());

    Ok(hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_curve() {
        let secret = "0000000000000000000000000000000000000000000000000000000000000000";
        let sec_hex = hex::decode(secret).unwrap();

        let y = hash_to_curve(&sec_hex).unwrap();
        let expected_y = PublicKey::from_hex(
            "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725",
        )
        .unwrap();
        assert_eq!(y, expected_y);

        let secret = "0000000000000000000000000000000000000000000000000000000000000001";
        let sec_hex = hex::decode(secret).unwrap();
        let y = hash_to_curve(&sec_hex).unwrap();
        let expected_y = PublicKey::from_hex(
            "022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf",
        )
        .unwrap();
        assert_eq!(y, expected_y);
        // Note that this message will take a few iterations of the loop before finding
        // a valid point
        let secret = "0000000000000000000000000000000000000000000000000000000000000002";
        let sec_hex = hex::decode(secret).unwrap();
        let y = hash_to_curve(&sec_hex).unwrap();
        let expected_y = PublicKey::from_hex(
            "026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f",
        )
        .unwrap();
        assert_eq!(y, expected_y);
    }

    #[test]
    fn test_hash_e() {
        let r1 = "020000000000000000000000000000000000000000000000000000000000000001";
        let r2 = "020000000000000000000000000000000000000000000000000000000000000001";
        let k = "020000000000000000000000000000000000000000000000000000000000000001";
        let c_ = "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2";

        let expected_e = "a4dc034b74338c28c6bc3ea49731f2a24440fc7c4affc08b31a93fc9fbe6401e";

        let e = hash_e(r1, r2, k, c_).unwrap();

        assert_eq!(expected_e, e);
    }
}
