#![cfg(feature = "rsa4096")]

use trussed::client::mechanisms::Rsa4096Pkcs;
use trussed::client::CryptoClient;
use trussed::syscall;
use trussed::types::KeyId;

mod client;

use trussed::types::KeySerialization;
use trussed::types::Location::*;
use trussed::types::StorageAttributes;

use hex_literal::hex;

// Tests below can be run on a PC using the "virt" feature

#[test]
fn rsa4096pkcs_generate_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa4096pkcs_private_key(Internal)).key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(sk, KeyId::from_special(0));
    })
}

#[test]
fn rsa4096pkcs_derive_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa4096pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa4096pkcs_public_key(sk, Volatile)).key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(pk, KeyId::from_special(0));
    })
}

#[test]
fn rsa4096pkcs_exists_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa4096pkcs_private_key(Internal)).key;
        let key_exists = syscall!(client.exists(trussed::types::Mechanism::Rsa4096Pkcs, sk)).exists;

        assert!(key_exists);
    })
}

#[test]
fn rsa4096pkcs_serialize_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa4096pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa4096pkcs_public_key(sk, Volatile)).key;

        let serialized_key =
            syscall!(client.serialize_rsa4096pkcs_key(pk, KeySerialization::Pkcs8Der))
                .serialized_key;

        assert!(!serialized_key.is_empty());
    })
}

#[test]
fn rsa4096pkcs_deserialize_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa4096pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa4096pkcs_public_key(sk, Volatile)).key;
        let serialized_key =
            syscall!(client.serialize_rsa4096pkcs_key(pk, KeySerialization::Pkcs8Der))
                .serialized_key;
        let location = StorageAttributes::new().set_persistence(Volatile);

        let deserialized_key_id = syscall!(client.deserialize_rsa4096pkcs_key(
            &serialized_key,
            KeySerialization::Pkcs8Der,
            location
        ))
        .key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(deserialized_key_id, KeyId::from_special(0));
    })
}

#[test]
fn rsa4096pkcs_sign_verify() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa4096pkcs_private_key(Volatile)).key;
        let hash_prefix = hex!("3051 300d 0609 608648016503040203 0500 0440");
        let message = [1u8, 2u8, 3u8];
        use sha2::digest::Digest;
        let digest_to_sign: Vec<u8> = sha2::Sha512::digest(&message)
            .into_iter()
            .chain(hash_prefix)
            .collect();
        let signature = syscall!(client.sign_rsa4096pkcs(sk, &digest_to_sign)).signature;

        // println!("Message: {:?}", &message);
        // println!("Digest: {:?}", &digest_to_sign);
        // println!("Signature (len={}): {:?}", signature.len(), &signature);

        let verify_ok = syscall!(client.verify_rsa4096pkcs(sk, &digest_to_sign, &signature)).valid;

        assert_eq!(signature.len(), 512);
        assert!(verify_ok);
    })
}
