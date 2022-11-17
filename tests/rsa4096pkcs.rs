#![cfg(feature = "rsa4096")]

use trussed::client::mechanisms::Rsa4096Pkcs;
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
        let digest = sha2::Sha512::digest(&message);
        let digest_to_sign: Vec<u8> = hash_prefix.into_iter().chain(digest).collect();
        let signature = syscall!(client.sign_rsa4096pkcs(sk, &digest_to_sign)).signature;

        // println!("Message: {:?}", &message);
        // println!("Digest: {:?}", &digest_to_sign);
        // println!("Signature (len={}): {:?}", signature.len(), &signature);

        let verify_ok = syscall!(client.verify_rsa4096pkcs(sk, &digest_to_sign, &signature)).valid;

        assert_eq!(signature.len(), 512);
        assert!(verify_ok);
    })
}

#[test]
fn rsa4096pkcs_inject() {
    client::get(|client| {
        let n  = hex!("adc511a420f48ffcb2c62f1a5113fe4e7f3efa20b0c6e711b93aca7e5ad662ba089ac27e9a1ae4cda8032d0b1ec8e3f719f6d3a04e1572a35caec922b439d53324b020d07e3ff70de2fb53409d26af1034b8f8fbf3776b1decd515af1298d98a671e3b2fd871f1b38c8917ed15c8732f96f75166df782d190913653a21da5d0647abc63c5b157910c455a4ac10d8ca3123ccdb98baf947e3a9ab9bff34fa9b0a19ab61f82c560ca46bad10391e49ef2bf5f01f198db12225338d68b0b18eaab962686e6a445b943952981fdf4c6f8135b6e86b1658d930df7fc2288c178401784a90977d1cf4444b401dabe2ebc6448979f74930aab7933a2fadc4c7b96c2fc65e85b2c49f0fa48381928ba64466b7c13303f8fa4b4afd5ad98e9d0990211a2b80caf6b071301e63d9f46b5d52016ec239e983efc1f6a0cd39a1fb9ae91483cc63f1467d13550802aab45ee03223ab1c13bdd82d79c4575f1bc4179ee9d7183534dd27b0a240497b951338fd29f863ff769140a4251219e61ef1ec8274d48431b58f7201c9069499488ac6c9e13e1ed790df14987760ef568a9fae55fd14e4e85232a345e265fb0ace01a0dc10a5390f67c9dba1de7d90b5b542eaaa370d935e153c97e82fe5108d9065991ad65181b2a2136d1474f91b3b85167cd3c04bdc6d144c4034b96b6be93b33c6d14bb511ffc04659cf807cbfd5039f68fb2ebe8ae9");
        let e = hex!("010001");
        let d  = hex!("974447d9127f12a0ad976c0582b2dedbc255363422eee2d340e576c48b9ab892ad4edb248e4dff032fd0a3f35c37108b5864cf506ae8acc49cb7e28b7d4c22d5c48835e8891e7197fb114125ac27b2996eebde82a52c3d68ed7388cec067a267a2e06431803fa061e662a91b4fad10e84a88bca9cabab8b7647927d37508bb95edea1045161d19288960ec5a84c7d32af7b92b28470b1d93876dc5fc61480e92ba49c09ce32b7d11dc51e91f6fc87895522057524d4ff7235f3f27f5387bb30e7225ea88433d5d489127b0071868b097ebc363052f0ed2469cd68da9760709a887705b0f249756");

        let p1 = hex!("cb4b267410739733134e5c7d21f042db821d3bf1e20b036de71cb40f175b3ddc8a164155223c5fec1df598fd5c314e9bc622c9c01fb3c70b1712b9f77d2ed6de5e9fe5b6dbfd789cedff5acff7d2bf0587bc071d43552f671e5392f69f7b16820bc2bec80b28f1eb42bbf2b99bd31eab59c479d2cd66550a7cf8d000b1c0e9c82460791a722bcd1945e134180b94ebf52026f0ee731cc63c38958f2fa5049ddac4cf55f57240f98afc51ff21a3379b16eba3974bb70623ec06afe6cd2d26041611c7b3b799090103fc0df8973aa1919a2ae65ccd1f484ccc5da4975ace0e96a2c3c0001c9b293b908d5585da5c0bb61ff5c17c20a0bd946a8df4fb7dd98cb44d");
        let p2 = hex!("dad263cb9b3c236859da7ecc6ec5f2154404dedf07cf39c7fd80ec2206384e906f001cf42ca690ab59a2aa73a2c78dfa4d5874a182ac92d7bd15161da7582fef30871b60afefee476944e32b41c482f71ceb6c476a5fccb2f65d8d382674a94b5abb4127bc4d8361bffbe8358f577875a0e0e8e1a975b00d8c3509a6566a1a2cd32d42a744b6785806566453903ebe420c6ea9a7eb2becc68cee40b81bee5e9957ccb7a3297545811e72b1b4e73b985ff30aff9abfb04c81b4937d8312f856098f15cf81c66ea2c6d94459ce25d4364e7d8c2aeaa6eace5b3054c976a8eb292fde2839503fb4444ba133c58fd1de38a995001af6af42661bcc6f18b1081c6f0d");
        let qinv = hex!("a9d2a72964e107db09dce8d345e35487b9f0e6eed1bceb64ed07d8580c0cacdb0641805083787109ae99fe705b426522b837953f05e9a204a277cebdde3e9d8a3e4e4e98f76764615f8028bb1a849cc125c7b11bc881ce08dd8fff72f1fda92fb893d79fc85555af021ad0d4c22f32dbfaacfaa3fd58d397fcb0904b267218374fa1b7ee7b06e6417aeeff428559b252c89fa41427506de6333d96b9ceac62648bb9743f7b4860c66a5e7fab0183ab7600887d947073e6b546adab857481943e3bcd3f88a98ae0febeaeddd71bce34514a8d1a9ebdba00e523f68dc28195cc7a4a1df133dd3d1866a97292fad735776b458750022fb1f4c79e7a3dbcb8bed893");

        let dp = hex!("69dac6ba16bae99719cd6ad169739e8c8812cadce753cec4525c1ad1e4da88baa658724a6f1a3ae44ab150a95471043a8e901cb7628a8cf1146196ddec9c101c17ef7080a7ca331c9bbca43fb80e4f93049b7ea4d923a91c2ba95ed3f634f48260b755f9f9fda702566c61360e927edcc0505312d60b1beaeb29efbcfcd1b3a9986f777fb2c565f56bf298da906549fc0872de6f7b17178dd1f4e66aeba51cc1064be3b97b75a3baa029de0c58dda26eebe1f1ece5ef579315e44fecb43ea050119007df68db4c6113c4fe95585d3ae0a8c7ecb88e3a6a6adbb3d16fe1edacb831ef6edf7657a10162e68e5d26229f01c348ad669bec3b34c49834bfd220b6dd");
        let dq = hex!("62beaa3609193c492cb302a13223b5388f773b339e0c8f60862f155fcd3abf8941ede522f2bb3f7173838a33a07338c888faafb6ea8701c4c518ace038d1fcdf8d208ae438c0a6e026cae55071df41d24d84975a2ad08c48fe0ffd58275261cb156886e06d82f514b953edd7ad95a5503f86fed0466e4b41f1d14547809b64b071a36cfe9a6d552533c6ec8321068f48b2df8543b7461d150427c7a0cd49e5fa80ba6aec001b618000c37519d376fb2de139475b07c180e4cf1df7779ca9dff9744e3d53acbde44aa364cab9d22c4f4d602e4e7791574843b22db0b41149fd4e128c4840c45e8eab2a5578838c0b21bab4f8553298a7f7f7f76af2d3807b8449");

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
            Mechanism::Rsa4096Pkcs,
            &data,
            Volatile,
            KeySerialization::RsaCrt
        ))
        .key;

        let hash_prefix = hex!("3051 300d 0609 608648016503040203 0500 0440");
        let message = [1u8, 2u8, 3u8];
        use sha2::digest::Digest;
        let digest = sha2::Sha512::digest(&message);
        let digest_to_sign: Vec<u8> = hash_prefix.into_iter().chain(digest).collect();

        let signature = syscall!(client.sign_rsa4096pkcs(sk, &digest_to_sign)).signature;
        assert!(pk
            .verify(
                PaddingScheme::PKCS1v15Sign {
                    hash: Some(Hash::SHA2_512)
                },
                &digest,
                &signature
            )
            .is_ok());
    });
}
