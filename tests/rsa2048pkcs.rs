#![cfg(feature = "rsa2048")]

use trussed::client::mechanisms::Rsa2048Pkcs;
use trussed::client::CryptoClient;
use trussed::syscall;
use trussed::types::KeyId;
use trussed::Bytes;

mod client;

use trussed::types::KeySerialization;
use trussed::types::Location::*;
use trussed::types::Mechanism;
use trussed::types::RsaCrtImportFormat;
use trussed::types::StorageAttributes;

use hex_literal::hex;
use num_bigint_dig::BigUint;
use rsa::hash::Hash;
use rsa::padding::PaddingScheme;
use rsa::{PublicKey, RsaPrivateKey};

// Tests below can be run on a PC using the "virt" feature

#[test]
fn rsa2048pkcs_generate_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa2048pkcs_private_key(Internal)).key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(sk, KeyId::from_special(0));
    })
}

#[test]
fn rsa2048pkcs_derive_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa2048pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa2048pkcs_public_key(sk, Volatile)).key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(pk, KeyId::from_special(0));
    })
}

#[test]
fn rsa2048pkcs_exists_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa2048pkcs_private_key(Internal)).key;
        let key_exists = syscall!(client.exists(trussed::types::Mechanism::Rsa2048Pkcs, sk)).exists;

        assert!(key_exists);
    })
}

#[test]
fn rsa2048pkcs_serialize_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa2048pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa2048pkcs_public_key(sk, Volatile)).key;

        let serialized_key =
            syscall!(client.serialize_rsa2048pkcs_key(pk, KeySerialization::Pkcs8Der))
                .serialized_key;

        assert!(!serialized_key.is_empty());
    })
}

#[test]
fn rsa2048pkcs_deserialize_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa2048pkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa2048pkcs_public_key(sk, Volatile)).key;
        let serialized_key =
            syscall!(client.serialize_rsa2048pkcs_key(pk, KeySerialization::Pkcs8Der))
                .serialized_key;
        let location = StorageAttributes::new().set_persistence(Volatile);

        let deserialized_key_id = syscall!(client.deserialize_rsa2048pkcs_key(
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
fn rsa2048pkcs_sign_verify() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa2048pkcs_private_key(Volatile)).key;
        let hash_prefix = hex!("3031 300d 0609 608648016503040201 0500 0420");
        let message = [1u8, 2u8, 3u8];
        use sha2::digest::Digest;
        let digest_to_sign: Vec<u8> = sha2::Sha256::digest(&message)
            .into_iter()
            .chain(hash_prefix)
            .collect();
        let signature = syscall!(client.sign_rsa2048pkcs(sk, &digest_to_sign)).signature;

        // println!("Message: {:?}", &message);
        // println!("Digest: {:?}", &digest_to_sign);
        // println!("Signature (len={}): {:?}", signature.len(), &signature);

        let verify_ok = syscall!(client.verify_rsa2048pkcs(sk, &digest_to_sign, &signature)).valid;

        assert_eq!(signature.len(), 256);
        assert!(verify_ok);
    })
}

#[test]
fn rsa2048pkcs_inject() {
    client::get(|client| {
        let n = hex!("b43f96eee6abf0e71d81244f9adcc049c379f22a40d99e0a921fca08c1a83695f2060eeebc52823e8fa59f61156e42119758c3937c848a69e13a4a3ee23f35bb923a63b7d0cec6092957ff038b58c63339f300fb0d6dfc3d239fb8ef2caafbb40ca98fbd795e6ab5128a6e880b72a0637bfb197ea6697cd045c648d2a55f0f0e181d6bb50e56f297c8da164a3b04fab69e66107a7767e3a2c1df5e655c40db3e76e469e6db71b2d4edd73d48eee894d3c6c8e966bc2153256b014bc63a8f02c59a06b89004903ec4887ac916e2f7c5077b93eef17e914bb07add9dced384946f89d99ba48b28eedcc511ce359d2b2bce8052181f229033b6f2b1a905a55b33bd");
        let e = hex!("010001");
        let d = hex!("0ac47db4b9ccedb030c00536482f05c1a24ec79ba4921b71d036dbefd7f9bf81079b3b0b21eedfdef2dfd6fc8ab63276308f59e79699a85718e04d8d2220da89e0fb61f79a1eb00fde0b66ad848682188f4ea7f15765099b71645a3cd773436407199dff989f7e4a60d82a303056e1a3efc51949ca9124a6a0746ee73e7fc63b5c9df7e15be95b3f83dbb81a3a95284b52ca584fd058e9dbe74285b85b13688225c72cfc4c636950553aa31670de8dac45abac75e8872ee623f6cb0974c1915600bfc8e5c60e38101ae558ab3400d540b1db36b5eb6d9a0674ddbb814b69258ef15a0a3d07d557856a30af72d5c8ebc26d8cb067be783a5aea564afba4e28181");
        let p1 = hex!("ccefc3c11c7a0ed08aa3994c7ebe4ec9fabd1d83ff20c0e203ab1f230ae1ca158b6b6e82661f6ba179acb8ce5eca858abaf1987660748b78f00fc14bfb8fe1569fa7ac71276ce8cc1e1e9679fdfb589e538f6ccdab3b3fe26121a2d0f8d5721daea8104f61569f5f634fcd4c202788e46c1e39295d29b07a410ed4d023577fe1");
        let p2 = hex!("e1290bd8c19fbd77eb271fd081a96af60cc33a9e8b0fffb751b1ed557d8653f39bce97a4733f7725f2b26050317fc816698c3d8ba8b2a3198f167c6708fbb96d45b6c1ff6a1e4b07752f6f316a60d8559904466e3ad04b7d9cf56efda9dfeaaadb74caa0079933c7d063ee80ea4bca73c4e0a20dd7b61a6886666359cec59f5d");

        let dp = hex!("962ea2faf2be73fad98e987a196ba75b97175df8ec4f796a681bd03ea2ebe267357bae497b434d61d144054e9ee2b5487c452e6099c0eeb0dae400d888eae0ccd5455036c018ace560b133bf04a45c45f2a069b0b2ea419fc96497e7a262f134d558ae532dd7080624464801a092b85c04eb85224df68e30995aa01443c20ca1");
        let dq = hex!("7577a39d970e8e9b948c19d5feff733520dd6da4af2a4e9fc6384c78b07f37273ddf1f50056c53edf15b4c522a30df238a374718a88f61f600a79b8969af6242f6feece122ece0f9e812323196ad25d02a7f877b14a5fcec70c9bef909fa2f04aa6f9912ba441c369faab31080abbfd87c1b3190853c95347901cbcd5bc9d065");
        let qinv = hex!("95de753d794227b41134152b071cf490efe78af52e5667cb18119b8a61c1523ecd0c8f38a8b73e64aea5ea098c15f838d995848d364d32cfca7c2e91934b9db04f97703f63125b7245de3eee91b9811131781906e940a60ec28fc754a7e610872311d15101371420590ee616561b9dcbe29a1b70d68d66de81220e0cab723e46");
        let raw = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&n),
            BigUint::from_bytes_be(&e),
            BigUint::from_bytes_be(&d),
            vec![BigUint::from_bytes_be(&p1), BigUint::from_bytes_be(&p2)],
        );
        let pk = raw.to_public_key();

        let request = RsaCrtImportFormat {
            e: &e,
            p: &p1,
            q: &p2,
            qinv: &qinv,
            dp: &dp,
            dq: &dq,
        };
        let data: Bytes<2048> = trussed::postcard_serialize_bytes(&request).unwrap();
        let sk = syscall!(client.unsafe_inject_key(
            Mechanism::Rsa2048Pkcs,
            &data,
            Volatile,
            KeySerialization::RsaCrt
        ))
        .key;

        let hash_prefix = hex!("3031 300d 0609 608648016503040201 0500 0420");
        let message = [1u8, 2u8, 3u8];
        use sha2::digest::Digest;
        let digest = sha2::Sha256::digest(&message);
        let digest_to_sign: Vec<u8> = hash_prefix.into_iter().chain(digest).collect();

        let signature = syscall!(client.sign_rsa2048pkcs(sk, &digest_to_sign)).signature;
        assert!(pk
            .verify(
                PaddingScheme::PKCS1v15Sign {
                    hash: Some(Hash::SHA2_256)
                },
                &digest,
                &signature
            )
            .is_ok());
    });
}
