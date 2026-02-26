//! BIP-340 Schnorr signature authentication.
//!
//! Auth token format: `{"pubkey":"hex","timestamp":number,"token":"hex_signature"}`
//! Message format: `llamenos:auth:{pubkey}:{timestamp}:{method}:{path}`
//! Signature: BIP-340 Schnorr over SHA-256(message)

use k256::schnorr::{SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::errors::CryptoError;
use crate::labels::AUTH_PREFIX;

/// A signed authentication token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub pubkey: String,
    pub timestamp: u64,
    pub token: String,
}

/// Create a Schnorr auth token for API authentication.
///
/// The message is bound to the specific request method + path to prevent
/// cross-endpoint replay attacks.
pub fn create_auth_token(
    secret_key_hex: &str,
    timestamp: u64,
    method: &str,
    path: &str,
) -> Result<AuthToken, CryptoError> {
    let mut sk_bytes = hex::decode(secret_key_hex).map_err(CryptoError::HexError)?;
    if sk_bytes.len() != 32 {
        return Err(CryptoError::InvalidSecretKey);
    }

    let signing_key = SigningKey::from_bytes(sk_bytes.as_slice().try_into().unwrap())
        .map_err(|_| CryptoError::InvalidSecretKey)?;
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = hex::encode(verifying_key.to_bytes());

    // Build message: llamenos:auth:{pubkey}:{timestamp}:{method}:{path}
    let message = format!("{AUTH_PREFIX}{pubkey_hex}:{timestamp}:{method}:{path}");
    let message_hash = {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        hasher.finalize()
    };

    // Sign with BIP-340 Schnorr
    let signature: k256::schnorr::Signature = signing_key.sign(&message_hash);
    let token_hex = hex::encode(signature.to_bytes());

    sk_bytes.zeroize();

    Ok(AuthToken {
        pubkey: pubkey_hex,
        timestamp,
        token: token_hex,
    })
}

/// Verify a Schnorr auth token.
///
/// Returns true if the signature is valid for the given method + path.
pub fn verify_auth_token(
    token: &AuthToken,
    method: &str,
    path: &str,
) -> Result<bool, CryptoError> {
    let pubkey_bytes = hex::decode(&token.pubkey).map_err(CryptoError::HexError)?;
    if pubkey_bytes.len() != 32 {
        return Err(CryptoError::InvalidPublicKey);
    }

    let verifying_key = VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap())
        .map_err(|_| CryptoError::InvalidPublicKey)?;

    let message = format!("{AUTH_PREFIX}{}:{}:{}:{}", token.pubkey, token.timestamp, method, path);
    let message_hash = {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        hasher.finalize()
    };

    let sig_bytes = hex::decode(&token.token).map_err(CryptoError::HexError)?;
    if sig_bytes.len() != 64 {
        return Err(CryptoError::SignatureVerificationFailed);
    }

    let signature = k256::schnorr::Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;

    match verifying_key.verify(&message_hash, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify a raw Schnorr signature over a message hash.
pub fn verify_schnorr(
    message_hex: &str,
    signature_hex: &str,
    pubkey_hex: &str,
) -> Result<bool, CryptoError> {
    let pubkey_bytes = hex::decode(pubkey_hex).map_err(CryptoError::HexError)?;
    if pubkey_bytes.len() != 32 {
        return Err(CryptoError::InvalidPublicKey);
    }

    let verifying_key = VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap())
        .map_err(|_| CryptoError::InvalidPublicKey)?;

    let message = hex::decode(message_hex).map_err(CryptoError::HexError)?;
    let sig_bytes = hex::decode(signature_hex).map_err(CryptoError::HexError)?;

    let signature = k256::schnorr::Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;

    match verifying_key.verify(&message, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;

    #[test]
    fn roundtrip_auth_token() {
        let kp = generate_keypair();
        let timestamp = 1708900000000u64;
        let method = "POST";
        let path = "/api/auth/login";

        let token = create_auth_token(&kp.secret_key_hex, timestamp, method, path).unwrap();
        assert_eq!(token.pubkey, kp.public_key);
        assert_eq!(token.timestamp, timestamp);

        let valid = verify_auth_token(&token, method, path).unwrap();
        assert!(valid);
    }

    #[test]
    fn wrong_path_fails() {
        let kp = generate_keypair();
        let token = create_auth_token(&kp.secret_key_hex, 1708900000000, "POST", "/api/auth/login").unwrap();

        let valid = verify_auth_token(&token, "POST", "/api/notes").unwrap();
        assert!(!valid);
    }

    #[test]
    fn wrong_method_fails() {
        let kp = generate_keypair();
        let token = create_auth_token(&kp.secret_key_hex, 1708900000000, "POST", "/api/auth/login").unwrap();

        let valid = verify_auth_token(&token, "GET", "/api/auth/login").unwrap();
        assert!(!valid);
    }
}
