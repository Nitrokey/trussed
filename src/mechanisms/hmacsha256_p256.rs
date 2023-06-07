use crate::api::*;
use crate::error::Error;
use crate::service::*;

#[cfg(feature = "hmac-sha256-p256")]
impl DeriveKey for super::HmacSha256P256 {
    #[inline(never)]
    fn derive_key(
        keystore: &mut impl Keystore,
        request: &request::DeriveKey,
    ) -> Result<reply::DeriveKey, Error> {
        //TODO: this is identical as the HmacSha256 implementation, but stores the resulting key as Kind::P256
        use hmac::{Hmac, Mac};
        type HmacSha256P256 = Hmac<sha2::Sha256>;

        let key_id = request.base_key;
        let key = keystore.load_key(key::Secrecy::Secret, None, &key_id)?;
        if !matches!(key.kind, key::Kind::Symmetric(..) | key::Kind::Shared(..)) {
            // We have to disable this check for compatibility with fido-authenticator, see:
            // https://github.com/solokeys/fido-authenticator/issues/21
            warn!(
                "derive_key for HmacSha256P256 called with invalid key kind ({:?})",
                key.kind
            );
        }
        let shared_secret = key.material;

        let mut mac =
            HmacSha256P256::new_from_slice(shared_secret.as_ref()).map_err(|_| Error::InternalError)?;

        if let Some(additional_data) = &request.additional_data {
            mac.update(additional_data);
        }
        let derived_key: [u8; 32] = mac
            .finalize()
            .into_bytes()
            .try_into()
            .map_err(|_| Error::InternalError)?;
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Kind::P256,
            &derived_key,
        )?;

        Ok(reply::DeriveKey { key: key_id })
    }
}


#[cfg(not(feature = "hmac-sha256-p256"))]
impl DeriveKey for super::HmacSha256P256 {}

#[cfg(feature = "hmac-sha256-p256")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac() {
        let expected1 = [
            111, 176, 100, 219, 221, 79, 157, 119, 246, 23, 196, 57, 85, 6, 201, 243, 17, 168, 135,
            139, 137, 129, 236, 115, 170, 209, 159, 98, 111, 80, 173, 36,
        ];
        let data1 = b"test data 1";
        let res1: [u8; 32] = get_hmac(&data1[..])
            .unwrap()
            .finalize()
            .into_bytes()
            .try_into()
            .unwrap();
        assert_eq!(res1, expected1);

        let data2 = b"test data 2";
        let res2: [u8; 32] = get_hmac(&data2[..])
            .unwrap()
            .finalize()
            .into_bytes()
            .try_into()
            .unwrap();
        assert_ne!(res1, res2);

        let res3: [u8; 32] = get_hmac(&data2[..])
            .unwrap()
            .finalize()
            .into_bytes()
            .try_into()
            .unwrap();
        assert_eq!(res3, res2);
    }
}
