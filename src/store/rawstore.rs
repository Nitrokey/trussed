use crate::{
    error::Error,
    mechanisms,
    // service::ReadDirState,
    store::{self, Store},
    types::{
        DirEntry, Filesystem, LfsStorage, Location, Message, Metadata, PathBuf, RawStoreMode,
        ShortData, UserAttribute,
    },
    Bytes,
};
use littlefs2::path::Path;

use heapless::Vec;
//use heapless::consts::*;

// encrypt / decrypt
use block_modes::{BlockMode, Cbc};
// use block_modes::Cbc;
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::block_padding::ZeroPadding;

// TODO: perhaps use NoPadding and have client pad, to emphasize spec-conformance?
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

use sha2::digest::Digest;

use chacha20::ChaCha8Rng;
use rand_core::RngCore;

#[derive(Copy, Clone)]
pub struct RawStore {
    mode: RawStoreMode,
    symmetric_key: Option<[u8; 32]>,
}

impl RawStore {
    pub fn new(
        mode: RawStoreMode,
        store: impl Store,
        pin: Option<ShortData>,
        rng: Option<ChaCha8Rng>,
    ) -> Self {
        let mut symmetric_key = [0u8; 32];

        if mode == RawStoreMode::Encrypted {
            let key_filename = PathBuf::from("encryption-key");

            let res: Result<Bytes<128>, Error> =
                store::read(store, Location::Internal, &key_filename);
            debug_now!("pin: {:?}", pin);
            let pin_key = Self::get_pin_key(pin.unwrap()).into_vec();
            match res {
                // 'key_filename' not found, generate new key and save (encrypted) to 'key_filename'
                Err(e) => {
                    let mut new_key = [0u8; 32];
                    rng.unwrap().fill_bytes(&mut new_key);

                    symmetric_key.copy_from_slice(&new_key);
                    let content =
                        Self::encrypt_content(mode, &key_filename, pin_key.as_slice(), &new_key);
                    store::write(
                        store,
                        Location::Internal,
                        &key_filename,
                        content.into_vec().as_slice(),
                    );
                }
                // 'key_filename' found, extract symmetric key and use it
                Ok(data) => {
                    symmetric_key.copy_from_slice(&Self::decrypt_content(
                        mode,
                        &key_filename,
                        pin_key.as_slice(),
                        data,
                    ));
                }
            }
        }

        Self {
            mode,
            symmetric_key: Some(symmetric_key),
        }
    }

    fn encrypt_content(mode: RawStoreMode, path: &Path, key: &[u8], contents: &[u8]) -> Message {
        match mode {
            RawStoreMode::Unencrypted => Message::from_slice(contents).unwrap(),
            RawStoreMode::Encrypted => {
                let zero_iv = Self::get_iv(path);
                let cipher = Aes256Cbc::new_from_slices(key, &zero_iv).unwrap();
                let mut buffer = Message::from_slice(contents).unwrap();
                let l = contents.len();
                buffer.resize_default(l + (32 - l % 32));
                let ciphertext = cipher.encrypt(&mut buffer, l).unwrap();
                Message::from_slice(ciphertext).unwrap()
            }
        }
    }

    fn decrypt_content<const N: usize>(
        mode: RawStoreMode,
        path: &Path,
        key: &[u8],
        contents: Bytes<N>,
    ) -> Bytes<N> {
        match mode {
            RawStoreMode::Unencrypted => {
                //debug_now!("READ DATA LEN - N:{:?} len:{:?} data: {:?}", N, contents.len(), &contents[..10]);
                contents
            }
            RawStoreMode::Encrypted => {
                let zero_iv = Self::get_iv(path);
                let cipher = Aes256Cbc::new_from_slices(key, &zero_iv).unwrap();
                let mut buffer = contents.clone();
                let plaintext = cipher.decrypt(&mut buffer).unwrap();
                let out = Bytes::<N>::from_slice(plaintext).unwrap();
                //debug_now!("READ DATA LEN - N:{:?} len:{:?} data: {:?}", N, out.len(), &out[..10]);
                out
            }
        }
    }

    pub fn get_pin_key(pin: ShortData) -> Bytes<32> {
        let mut hash = sha2::Sha256::new();
        hash.update(pin);
        hash.update("pin-salt");

        let mut hashed = ShortData::new();
        hashed.extend_from_slice(&hash.finalize()).unwrap();
        Bytes::<32>::from_slice(&hashed.into_vec().as_slice()[..32]).unwrap()
    }

    pub fn get_iv(path: &Path) -> Bytes<16> {
        let mut hash = sha2::Sha256::new();
        hash.update(&path.as_str_ref_with_trailing_nul());
        hash.update("salt");

        let mut hashed = ShortData::new();
        hashed.extend_from_slice(&hash.finalize()).unwrap();
        Bytes::<16>::from_slice(&hashed.into_vec().as_slice()[..16]).unwrap()
    }

    pub fn create_directories<'s, S: LfsStorage>(
        &self,
        fs: &Filesystem<'s, S>,
        path: &Path,
    ) -> Result<(), Error> {
        store::create_directories(fs, path)
    }

    pub fn read<const N: usize>(
        &self,
        store: impl Store,
        location: Location,
        path: &Path,
    ) -> Result<Bytes<N>, Error> {
        debug_now!("READ: {:?} {:?}", N, path);
        store::read(store, location, path)
            .map(|val| Self::decrypt_content(self.mode, path, &self.symmetric_key.unwrap(), val))
    }

    pub fn write(
        &self,
        store: impl Store,
        location: Location,
        path: &Path,
        contents: &[u8],
    ) -> Result<(), Error> {
        debug_now!("WRITE: {:?} data: {:?}", path, &contents[..10]);
        let data = Self::encrypt_content(
            self.mode,
            path,
            &self.symmetric_key.unwrap(),
            &contents.clone(),
        );
        store::write(store, location, path, data.into_vec().as_slice())
    }

    pub fn store(
        &self,
        store: impl Store,
        location: Location,
        path: &Path,
        contents: &[u8],
    ) -> Result<(), Error> {
        debug_now!("STORE: {:?} data: {:?}", path, &contents[..10]);
        let data = Self::encrypt_content(
            self.mode,
            path,
            &self.symmetric_key.unwrap(),
            &contents.clone(),
        );
        store::store(store, location, path, data.into_vec().as_slice())
    }
    pub fn delete(&self, store: impl Store, location: Location, path: &Path) -> bool {
        store::delete(store, location, path)
    }

    pub fn exists(&self, store: impl Store, location: Location, path: &Path) -> bool {
        store::exists(store, location, path)
    }

    pub fn metadata(
        &self,
        store: impl Store,
        location: Location,
        path: &Path,
    ) -> Result<Option<Metadata>, Error> {
        store::metadata(store, location, path)
    }

    pub fn remove_dir(&self, store: impl Store, location: Location, path: &Path) -> bool {
        store::remove_dir(store, location, path)
    }

    pub fn remove_dir_all_where<P>(
        &self,
        store: impl Store,
        location: Location,
        path: &Path,
        predicate: P,
    ) -> Result<usize, Error>
    where
        P: Fn(&DirEntry) -> bool,
    {
        store::remove_dir_all_where(store, location, path, predicate)
    }
}
