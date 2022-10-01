use rsa::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
    PublicKey, RsaPrivateKey, RsaPublicKey,
};

use crate::api::*;
// use crate::config::*;
// use crate::debug;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

#[cfg(feature = "rsa2k")]
impl DeriveKey for super::Rsa2kPkcs {
    #[inline(never)]
    fn derive_key(
        keystore: &mut impl Keystore,
        request: &request::DeriveKey,
    ) -> Result<reply::DeriveKey, Error> {
        // Retrieve private key
        let base_key_id = &request.base_key;

        // std::println!("Loading key: {:?}", base_key_id);

        let priv_key_der = keystore
            .load_key(key::Secrecy::Secret, Some(key::Kind::Rsa2k), base_key_id)
            .expect("Failed to load an RSA 2K private key with the given ID")
            .material;

        // std::println!("Loaded key material: {}", delog::hex_str!(&priv_key_der));
        // std::println!("Key material length is {}", priv_key_der.len());

        let priv_key = DecodePrivateKey::from_pkcs8_der(&priv_key_der)
            .expect("Failed to deserialize an RSA 2K private key from PKCS#8 DER");

        // Derive and store public key
        let pub_key_der = RsaPublicKey::from(&priv_key)
            .to_public_key_der()
            .expect("Failed to derive an RSA 2K public key or to serialize it to PKCS#8 DER");

        let pub_key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public,
            key::Kind::Rsa2k,
            pub_key_der.as_ref(),
        )?;

        // Send a reply
        Ok(reply::DeriveKey { key: pub_key_id })
    }
}

#[cfg(feature = "rsa2k")]
impl DeserializeKey for super::Rsa2kPkcs {
    #[inline(never)]
    fn deserialize_key(
        keystore: &mut impl Keystore,
        request: &request::DeserializeKey,
    ) -> Result<reply::DeserializeKey, Error> {
        // - mechanism: Mechanism
        // - serialized_key: Message
        // - attributes: StorageAttributes

        if request.format != KeySerialization::Raw {
            return Err(Error::InternalError);
        }

        let private_key: RsaPrivateKey = DecodePrivateKey::from_pkcs8_der(&request.serialized_key)
            .map_err(|_| Error::InvalidSerializedKey)?;

        // We store our keys in PKCS#8 DER format
        let private_key_der = private_key
            .to_pkcs8_der()
            .expect("Failed to serialize an RSA 2K private key to PKCS#8 DER");

        let private_key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Kind::Rsa2k,
            private_key_der.as_ref(),
        )?;

        Ok(reply::DeserializeKey {
            key: private_key_id,
        })
    }
}

#[cfg(feature = "rsa2k")]
impl GenerateKey for super::Rsa2kPkcs {
    #[inline(never)]
    fn generate_key(
        keystore: &mut impl Keystore,
        request: &request::GenerateKey,
    ) -> Result<reply::GenerateKey, Error> {
        // We want an RSA 2K key
        let bits = 2048;

        let priv_key = RsaPrivateKey::new(keystore.rng(), bits)
            .expect("Failed to generate an RSA 2K private key");

        // std::println!("Stored key material before DER: {:#?}", priv_key);

        let priv_key_der = priv_key
            .to_pkcs8_der()
            .expect("Failed to serialize an RSA 2K private key to PKCS#8 DER");

        // std::println!("Stored key material after DER: {}", delog::hex_str!(&priv_key_der));
        // std::println!("Key material length is {}", priv_key_der.as_ref().len());
        // #[cfg(all(test, feature = "verbose-tests"))]
        // std::println!("rsa2k-pkcs private key = {:?}", &private_key);

        // store the key
        let priv_key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Info::from(key::Kind::Rsa2k).with_local_flag(),
            priv_key_der.as_ref(),
        )?;

        // return handle
        Ok(reply::GenerateKey { key: priv_key_id })
    }
}

use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;

#[cfg(feature = "rsa2k")]
impl SerializeKey for super::Rsa2kPkcs {
    #[inline(never)]
    fn serialize_key(
        keystore: &mut impl Keystore,
        request: &request::SerializeKey,
    ) -> Result<reply::SerializeKey, Error> {
        let key_id = request.key;

        // We rely on the fact that we store the keys in the PKCS#8 DER format already
        let priv_key_der = {
            let res = keystore.load_key(key::Secrecy::Secret, Some(key::Kind::Rsa2k), &key_id);
            if res.is_ok() {
                res.expect("Failed to load an RSA 2K private key with the given ID")
            } else {
                keystore
                    .load_key(key::Secrecy::Public, Some(key::Kind::Rsa2k), &key_id)
                    .expect("Failed to load an RSA 2K private key with the given ID")
            }
        }
        .material;

        let serialized_key = match request.format {
            KeySerialization::Raw => {
                let mut serialized_key = Message::new();
                serialized_key
                    .extend_from_slice(&priv_key_der)
                    .map_err(|_| Error::InternalError)?;
                serialized_key
            }
            KeySerialization::RsaPkcs1 => {
                // TODO make sure this is only for the public key
                // pkcs1::EncodeRsaPublicKey
                let public_key =
                    RsaPublicKey::from_public_key_der(priv_key_der.as_slice()).unwrap();
                heapless_bytes::Bytes::from_slice(public_key.to_pkcs1_der().unwrap().as_ref())
                    .unwrap()
            }
            _ => {
                return Err(Error::InternalError);
            }
        };
        Ok(reply::SerializeKey { serialized_key })
    }
}

#[cfg(feature = "rsa2k")]
impl Exists for super::Rsa2kPkcs {
    #[inline(never)]
    fn exists(
        keystore: &mut impl Keystore,
        request: &request::Exists,
    ) -> Result<reply::Exists, Error> {
        let key_id = request.key;

        let exists = keystore.exists_key(key::Secrecy::Secret, Some(key::Kind::Rsa2k), &key_id);
        Ok(reply::Exists { exists })
    }
}

#[cfg(feature = "rsa2k")]
impl Sign for super::Rsa2kPkcs {
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign) -> Result<reply::Sign, Error> {
        // First, get the key
        let key_id = request.key;

        // We rely on the fact that we store the keys in the PKCS#8 DER format already
        let priv_key_der = keystore
            .load_key(key::Secrecy::Secret, Some(key::Kind::Rsa2k), &key_id)
            .expect("Failed to load an RSA 2K private key with the given ID")
            .material;

        let priv_key: RsaPrivateKey = DecodePrivateKey::from_pkcs8_der(&priv_key_der)
            .expect("Failed to deserialize an RSA 2K private key from PKCS#8 DER");

        // RSA lib takes in a hash value to sign, not raw data.
        // We assume we get digest into this function, too.

        // TODO: Consider using .sign_blinded(), which is supposed to protect the private key from timing side channels
        use rsa::hash::Hash;
        use rsa::padding::PaddingScheme;
        let native_signature = priv_key
            .sign(
                PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256)),
                &request.message,
            )
            .unwrap();
        let our_signature = Signature::from_slice(&native_signature).unwrap();

        // std::println!("RSA2K-PKCS_v1.5 signature:");
        // std::println!("msg: {:?}", &request.message);
        // std::println!("pk:  {:?}", &priv_key);
        // std::println!("sig: {:?}", &our_signature);

        // return signature
        Ok(reply::Sign {
            signature: our_signature,
        })
    }
}

#[cfg(feature = "rsa2k")]
impl Verify for super::Rsa2kPkcs {
    #[inline(never)]
    fn verify(
        keystore: &mut impl Keystore,
        request: &request::Verify,
    ) -> Result<reply::Verify, Error> {
        if let SignatureSerialization::Raw = request.format {
        } else {
            return Err(Error::InvalidSerializationFormat);
        }

        // TODO: This must not be a hardcoded magic number, convert when a common mechanism is available
        if request.signature.len() != 256 {
            return Err(Error::WrongSignatureLength);
        }

        let key_id = request.key;

        let priv_key_der = keystore
            .load_key(key::Secrecy::Secret, Some(key::Kind::Rsa2k), &key_id)
            .expect("Failed to load an RSA 2K private key with the given ID")
            .material;

        let priv_key = DecodePrivateKey::from_pkcs8_der(&priv_key_der)
            .expect("Failed to deserialize an RSA 2K private key from PKCS#8 DER");

        // Get the public key
        let pub_key = RsaPublicKey::from(&priv_key);

        use rsa::hash::Hash;
        use rsa::padding::PaddingScheme;
        let verification_ok = pub_key
            .verify(
                PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256)),
                &request.message,
                &request.signature,
            )
            .is_ok();

        Ok(reply::Verify {
            valid: verification_ok,
        })
    }
}

#[cfg(not(feature = "rsa2k"))]
impl DeriveKey for super::Rsa2kPkcs {}
#[cfg(not(feature = "rsa2k"))]
impl GenerateKey for super::Rsa2kPkcs {}
#[cfg(not(feature = "rsa2k"))]
impl Sign for super::Rsa2kPkcs {}
#[cfg(not(feature = "rsa2k"))]
impl Verify for super::Rsa2kPkcs {}
