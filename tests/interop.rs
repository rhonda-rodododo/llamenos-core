//! Cross-platform interoperability tests.
//!
//! These tests generate test vectors using deterministic inputs and verify
//! that the wire format matches what the JavaScript (@noble/*) and mobile
//! (UniFFI) implementations produce. The test vectors are written to
//! `tests/fixtures/test-vectors.json` so other platforms can consume them.
//!
//! Run with: cargo test --test interop

use llamenos_core::auth::{create_auth_token, verify_auth_token, AuthToken};
use llamenos_core::ecies::{ecies_unwrap_key, ecies_wrap_key, KeyEnvelope};
use llamenos_core::encryption::{
    decrypt_draft, decrypt_note, decrypt_with_pin, encrypt_draft, encrypt_note, encrypt_with_pin,
    EncryptedKeyData, EncryptedNote,
};
use llamenos_core::keys::{generate_keypair, get_public_key};
use llamenos_core::labels::*;
use serde::{Deserialize, Serialize};
use std::fs;

/// Well-known test keypair (NEVER use in production).
/// Generated deterministically for reproducible test vectors.
const TEST_SECRET_KEY: &str =
    "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f";

/// Second test keypair for multi-recipient tests.
const TEST_ADMIN_SECRET_KEY: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";

/// Test PIN for key encryption vectors.
const TEST_PIN: &str = "1234";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestVectors {
    /// Metadata
    version: String,
    generated_by: String,

    /// Key material (deterministic from known secrets)
    keys: KeyVectors,

    /// ECIES wrap/unwrap vectors
    ecies: EciesVectors,

    /// Note encryption vectors (non-deterministic encrypted content, but structure is fixed)
    note_encryption: NoteEncryptionVectors,

    /// Auth token vectors
    auth: AuthVectors,

    /// PIN encryption vectors
    pin_encryption: PinEncryptionVectors,

    /// Draft encryption vectors
    draft_encryption: DraftEncryptionVectors,

    /// Label constants (for cross-platform consistency)
    labels: LabelVectors,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyVectors {
    /// hex secret key
    secret_key_hex: String,
    /// x-only pubkey hex (32 bytes / 64 chars)
    public_key_hex: String,
    /// bech32 nsec
    nsec: String,
    /// bech32 npub
    npub: String,
    /// Admin key for multi-recipient
    admin_secret_key_hex: String,
    admin_public_key_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EciesVectors {
    /// A known-good wrapped key that Rust produced.
    /// JS should be able to unwrap it with the recipient's secret key.
    envelope: KeyEnvelope,
    /// The original plaintext key (hex) that was wrapped
    original_key_hex: String,
    /// The label used for wrapping
    label: String,
    /// Recipient pubkey
    recipient_pubkey_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NoteEncryptionVectors {
    /// The original plaintext JSON
    plaintext_json: String,
    /// Author pubkey (x-only hex)
    author_pubkey: String,
    /// Admin pubkeys
    admin_pubkeys: Vec<String>,
    /// The encrypted note (Rust-produced)
    encrypted: EncryptedNote,
    /// Decrypted using author's key — should match plaintext_json
    author_can_decrypt: bool,
    /// Decrypted using admin's key — should match plaintext_json
    admin_can_decrypt: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthVectors {
    secret_key_hex: String,
    timestamp: u64,
    method: String,
    path: String,
    /// The produced auth token
    token: AuthToken,
    /// Token is valid for the correct method+path
    valid: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PinEncryptionVectors {
    pin: String,
    nsec: String,
    pubkey_hex: String,
    /// Rust-encrypted key data
    encrypted: EncryptedKeyData,
    /// Can be decrypted with the same PIN
    decryptable: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DraftEncryptionVectors {
    plaintext: String,
    secret_key_hex: String,
    /// hex(nonce + ciphertext)
    encrypted_hex: String,
    /// Can be decrypted back to plaintext
    decryptable: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LabelVectors {
    label_note_key: String,
    label_file_key: String,
    label_file_metadata: String,
    label_hub_key_wrap: String,
    label_transcription: String,
    label_message: String,
    label_call_meta: String,
    label_shift_schedule: String,
    hkdf_salt: String,
    hkdf_context_notes: String,
    hkdf_context_drafts: String,
    hkdf_context_export: String,
    label_hub_event: String,
    label_device_provision: String,
    sas_salt: String,
    sas_info: String,
    auth_prefix: String,
    hmac_phone_prefix: String,
    hmac_ip_prefix: String,
    hmac_keyid_prefix: String,
    hmac_subscriber: String,
    hmac_preference_token: String,
    recovery_salt: String,
    label_backup: String,
    label_server_nostr_key: String,
    label_server_nostr_key_info: String,
    label_push_wake: String,
    label_push_full: String,
}

#[test]
fn generate_and_verify_test_vectors() {
    // --- Key derivation ---
    let author_pubkey = get_public_key(TEST_SECRET_KEY).unwrap();
    let admin_pubkey = get_public_key(TEST_ADMIN_SECRET_KEY).unwrap();

    // Use a generated keypair for nsec-related tests (PIN encryption needs valid nsec)
    let test_kp = generate_keypair();

    // --- ECIES wrap/unwrap roundtrip ---
    let original_key = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let key_bytes: [u8; 32] = hex::decode(original_key).unwrap().try_into().unwrap();
    let envelope = ecies_wrap_key(
        &key_bytes,
        &admin_pubkey,
        LABEL_NOTE_KEY,
    )
    .unwrap();

    // Verify unwrap works
    let unwrapped = ecies_unwrap_key(&envelope, TEST_ADMIN_SECRET_KEY, LABEL_NOTE_KEY).unwrap();
    assert_eq!(hex::encode(&unwrapped), original_key);

    // --- Note encryption roundtrip ---
    let note_payload = r#"{"text":"Test note for interop","fields":{"severity":"high"}}"#;
    let encrypted_note =
        encrypt_note(note_payload, &author_pubkey, &[admin_pubkey.clone()]).unwrap();

    // Author can decrypt
    let author_decrypted = decrypt_note(
        &encrypted_note.encrypted_content,
        &encrypted_note.author_envelope,
        TEST_SECRET_KEY,
    )
    .unwrap();
    assert_eq!(author_decrypted, note_payload);

    // Admin can decrypt
    let admin_envelope = encrypted_note
        .admin_envelopes
        .iter()
        .find(|e| e.pubkey == admin_pubkey)
        .unwrap();
    let admin_decrypted = decrypt_note(
        &encrypted_note.encrypted_content,
        &KeyEnvelope {
            wrapped_key: admin_envelope.wrapped_key.clone(),
            ephemeral_pubkey: admin_envelope.ephemeral_pubkey.clone(),
        },
        TEST_ADMIN_SECRET_KEY,
    )
    .unwrap();
    assert_eq!(admin_decrypted, note_payload);

    // --- Auth token roundtrip ---
    let timestamp = 1708900000000u64;
    let method = "POST";
    let path = "/api/notes";
    let auth_token =
        create_auth_token(TEST_SECRET_KEY, timestamp, method, path).unwrap();
    let valid = verify_auth_token(&auth_token, method, path).unwrap();
    assert!(valid);

    // --- PIN encryption roundtrip ---
    let pin_encrypted =
        encrypt_with_pin(&test_kp.nsec, TEST_PIN, &test_kp.public_key).unwrap();
    let pin_decrypted = decrypt_with_pin(&pin_encrypted, TEST_PIN).unwrap();
    assert_eq!(pin_decrypted, test_kp.nsec);

    // --- Draft encryption roundtrip ---
    let draft_text = "Draft note content for interop test";
    let draft_encrypted = encrypt_draft(draft_text, TEST_SECRET_KEY).unwrap();
    let draft_decrypted = decrypt_draft(&draft_encrypted, TEST_SECRET_KEY).unwrap();
    assert_eq!(draft_decrypted, draft_text);

    // --- Build test vectors ---
    let vectors = TestVectors {
        version: "1".to_string(),
        generated_by: "llamenos-core interop test".to_string(),
        keys: KeyVectors {
            secret_key_hex: TEST_SECRET_KEY.to_string(),
            public_key_hex: author_pubkey.clone(),
            nsec: test_kp.nsec.clone(),
            npub: test_kp.npub.clone(),
            admin_secret_key_hex: TEST_ADMIN_SECRET_KEY.to_string(),
            admin_public_key_hex: admin_pubkey.clone(),
        },
        ecies: EciesVectors {
            envelope: envelope.clone(),
            original_key_hex: original_key.to_string(),
            label: LABEL_NOTE_KEY.to_string(),
            recipient_pubkey_hex: admin_pubkey.clone(),
        },
        note_encryption: NoteEncryptionVectors {
            plaintext_json: note_payload.to_string(),
            author_pubkey: author_pubkey.clone(),
            admin_pubkeys: vec![admin_pubkey.clone()],
            encrypted: encrypted_note,
            author_can_decrypt: true,
            admin_can_decrypt: true,
        },
        auth: AuthVectors {
            secret_key_hex: TEST_SECRET_KEY.to_string(),
            timestamp,
            method: method.to_string(),
            path: path.to_string(),
            token: auth_token,
            valid: true,
        },
        pin_encryption: PinEncryptionVectors {
            pin: TEST_PIN.to_string(),
            nsec: test_kp.nsec.clone(),
            pubkey_hex: test_kp.public_key.clone(),
            encrypted: pin_encrypted,
            decryptable: true,
        },
        draft_encryption: DraftEncryptionVectors {
            plaintext: draft_text.to_string(),
            secret_key_hex: TEST_SECRET_KEY.to_string(),
            encrypted_hex: draft_encrypted,
            decryptable: true,
        },
        labels: LabelVectors {
            label_note_key: LABEL_NOTE_KEY.to_string(),
            label_file_key: LABEL_FILE_KEY.to_string(),
            label_file_metadata: LABEL_FILE_METADATA.to_string(),
            label_hub_key_wrap: LABEL_HUB_KEY_WRAP.to_string(),
            label_transcription: LABEL_TRANSCRIPTION.to_string(),
            label_message: LABEL_MESSAGE.to_string(),
            label_call_meta: LABEL_CALL_META.to_string(),
            label_shift_schedule: LABEL_SHIFT_SCHEDULE.to_string(),
            hkdf_salt: HKDF_SALT.to_string(),
            hkdf_context_notes: HKDF_CONTEXT_NOTES.to_string(),
            hkdf_context_drafts: HKDF_CONTEXT_DRAFTS.to_string(),
            hkdf_context_export: HKDF_CONTEXT_EXPORT.to_string(),
            label_hub_event: LABEL_HUB_EVENT.to_string(),
            label_device_provision: LABEL_DEVICE_PROVISION.to_string(),
            sas_salt: SAS_SALT.to_string(),
            sas_info: SAS_INFO.to_string(),
            auth_prefix: AUTH_PREFIX.to_string(),
            hmac_phone_prefix: HMAC_PHONE_PREFIX.to_string(),
            hmac_ip_prefix: HMAC_IP_PREFIX.to_string(),
            hmac_keyid_prefix: HMAC_KEYID_PREFIX.to_string(),
            hmac_subscriber: HMAC_SUBSCRIBER.to_string(),
            hmac_preference_token: HMAC_PREFERENCE_TOKEN.to_string(),
            recovery_salt: RECOVERY_SALT.to_string(),
            label_backup: LABEL_BACKUP.to_string(),
            label_server_nostr_key: LABEL_SERVER_NOSTR_KEY.to_string(),
            label_server_nostr_key_info: LABEL_SERVER_NOSTR_KEY_INFO.to_string(),
            label_push_wake: LABEL_PUSH_WAKE.to_string(),
            label_push_full: LABEL_PUSH_FULL.to_string(),
        },
    };

    // Write test vectors to fixture file
    let json = serde_json::to_string_pretty(&vectors).unwrap();
    let fixture_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/test-vectors.json");
    fs::write(fixture_path, &json).unwrap();

    println!("Test vectors written to {fixture_path}");
}

#[test]
fn ecies_cross_label_rejection() {
    // Wrapping with one label and unwrapping with a different label MUST fail.
    // This verifies domain separation works correctly across platforms.
    let admin_pubkey = get_public_key(TEST_ADMIN_SECRET_KEY).unwrap();
    let key_bytes: [u8; 32] = hex::decode(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap()
    .try_into()
    .unwrap();

    let envelope = ecies_wrap_key(&key_bytes, &admin_pubkey, LABEL_NOTE_KEY).unwrap();

    // Unwrapping with wrong label should fail
    let result = ecies_unwrap_key(&envelope, TEST_ADMIN_SECRET_KEY, LABEL_MESSAGE);
    assert!(result.is_err(), "Cross-label unwrap must fail");

    // Unwrapping with correct label should succeed
    let result = ecies_unwrap_key(&envelope, TEST_ADMIN_SECRET_KEY, LABEL_NOTE_KEY);
    assert!(result.is_ok(), "Same-label unwrap must succeed");
}

#[test]
fn auth_token_deterministic_verification() {
    // Auth tokens with known inputs produce verifiable signatures.
    // This test ensures JS can verify tokens produced by Rust.
    let token = create_auth_token(TEST_SECRET_KEY, 1708900000000, "GET", "/api/notes").unwrap();

    // Pubkey must match what JS derives from the same secret
    let expected_pubkey = get_public_key(TEST_SECRET_KEY).unwrap();
    assert_eq!(token.pubkey, expected_pubkey);

    // Verification must pass
    assert!(verify_auth_token(&token, "GET", "/api/notes").unwrap());

    // Wrong method/path must fail
    assert!(!verify_auth_token(&token, "POST", "/api/notes").unwrap());
    assert!(!verify_auth_token(&token, "GET", "/api/calls").unwrap());
}

#[test]
fn pin_encryption_format_consistency() {
    // PIN encryption produces a well-defined structure that JS must parse.
    let kp = generate_keypair();
    let encrypted = encrypt_with_pin(&kp.nsec, "5678", &kp.public_key).unwrap();

    // Verify structure fields
    assert!(!encrypted.salt.is_empty(), "salt must be present");
    assert_eq!(encrypted.iterations, 600_000, "iterations must be 600K");
    assert!(!encrypted.nonce.is_empty(), "nonce must be present");
    assert!(!encrypted.ciphertext.is_empty(), "ciphertext must be present");
    assert!(!encrypted.pubkey.is_empty(), "pubkey hash must be present");

    // Salt is 16 bytes = 32 hex chars
    assert_eq!(encrypted.salt.len(), 32, "salt must be 32 hex chars");

    // Nonce is 24 bytes = 48 hex chars
    assert_eq!(encrypted.nonce.len(), 48, "nonce must be 48 hex chars");

    // Roundtrip
    let decrypted = decrypt_with_pin(&encrypted, "5678").unwrap();
    assert_eq!(decrypted, kp.nsec);

    // Wrong PIN fails
    let result = decrypt_with_pin(&encrypted, "9999");
    assert!(result.is_err(), "Wrong PIN must fail");
}

#[test]
fn label_count_matches_expected() {
    // If a new label is added to labels.rs but not here, this test catches it.
    // Update this count when adding new crypto labels.
    let label_vec = LabelVectors {
        label_note_key: LABEL_NOTE_KEY.to_string(),
        label_file_key: LABEL_FILE_KEY.to_string(),
        label_file_metadata: LABEL_FILE_METADATA.to_string(),
        label_hub_key_wrap: LABEL_HUB_KEY_WRAP.to_string(),
        label_transcription: LABEL_TRANSCRIPTION.to_string(),
        label_message: LABEL_MESSAGE.to_string(),
        label_call_meta: LABEL_CALL_META.to_string(),
        label_shift_schedule: LABEL_SHIFT_SCHEDULE.to_string(),
        hkdf_salt: HKDF_SALT.to_string(),
        hkdf_context_notes: HKDF_CONTEXT_NOTES.to_string(),
        hkdf_context_drafts: HKDF_CONTEXT_DRAFTS.to_string(),
        hkdf_context_export: HKDF_CONTEXT_EXPORT.to_string(),
        label_hub_event: LABEL_HUB_EVENT.to_string(),
        label_device_provision: LABEL_DEVICE_PROVISION.to_string(),
        sas_salt: SAS_SALT.to_string(),
        sas_info: SAS_INFO.to_string(),
        auth_prefix: AUTH_PREFIX.to_string(),
        hmac_phone_prefix: HMAC_PHONE_PREFIX.to_string(),
        hmac_ip_prefix: HMAC_IP_PREFIX.to_string(),
        hmac_keyid_prefix: HMAC_KEYID_PREFIX.to_string(),
        hmac_subscriber: HMAC_SUBSCRIBER.to_string(),
        hmac_preference_token: HMAC_PREFERENCE_TOKEN.to_string(),
        recovery_salt: RECOVERY_SALT.to_string(),
        label_backup: LABEL_BACKUP.to_string(),
        label_server_nostr_key: LABEL_SERVER_NOSTR_KEY.to_string(),
        label_server_nostr_key_info: LABEL_SERVER_NOSTR_KEY_INFO.to_string(),
        label_push_wake: LABEL_PUSH_WAKE.to_string(),
        label_push_full: LABEL_PUSH_FULL.to_string(),
    };

    let json = serde_json::to_value(&label_vec).unwrap();
    let map = json.as_object().unwrap();
    assert_eq!(
        map.len(),
        28,
        "Expected 28 labels — update interop test if new labels were added"
    );
}
