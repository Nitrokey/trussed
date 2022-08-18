use chacha20::ChaCha8Rng;
use littlefs2::path::PathBuf;

use crate::{
    error::{Error, Result},
    store::rawstore::RawStore,
    store::Store,
    types::{CertId, Location, Message, RawStoreMode},
};

pub struct ClientCertstore<S>
where
    S: Store,
{
    client_id: PathBuf,
    rng: ChaCha8Rng,
    store: S,
    raw_store: RawStore,
}

pub trait Certstore {
    fn delete_certificate(&mut self, id: CertId) -> Result<()>;
    fn read_certificate(&mut self, id: CertId) -> Result<Message>;
    /// TODO: feels a bit heavy-weight to pass in the ClientCounterstore here
    /// just to ensure the next global counter ("counter zero") is used, and
    /// not something random.
    fn write_certificate(&mut self, location: Location, der: &Message) -> Result<CertId>;
}

impl<S: Store> Certstore for ClientCertstore<S> {
    fn delete_certificate(&mut self, id: CertId) -> Result<()> {
        let path = self.cert_path(id);
        let locations = [Location::Internal, Location::External, Location::Volatile];
        locations
            .iter()
            .any(|&location| self.raw_store.delete(self.store, location, &path))
            .then(|| ())
            .ok_or(Error::NoSuchKey)
    }

    fn read_certificate(&mut self, id: CertId) -> Result<Message> {
        let path = self.cert_path(id);
        let locations = [Location::Internal, Location::External, Location::Volatile];
        locations
            .iter()
            .find_map(|&location| self.raw_store.read(self.store, location, &path).ok())
            .ok_or(Error::NoSuchCertificate)
    }

    fn write_certificate(&mut self, location: Location, der: &Message) -> Result<CertId> {
        let id = CertId::new(&mut self.rng);
        let path = self.cert_path(id);
        self.raw_store
            .store(self.store, location, &path, der.as_slice())?;
        Ok(id)
    }
}

impl<S: Store> ClientCertstore<S> {
    pub fn new(client_id: PathBuf, rng: ChaCha8Rng, store: S, raw_store: RawStore) -> Self {
        Self {
            client_id,
            rng,
            store,
            raw_store,
        }
    }

    fn cert_path(&self, id: CertId) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(&self.client_id);
        path.push(&PathBuf::from("x5c"));
        path.push(&PathBuf::from(id.hex().as_slice()));
        path
    }

    // fn read_cert(&mut self, location: Location, id: u128) -> Result<Message> {
    //     let path = self.cert_path(id);
    //     let mut data: Message = store::read(self.store, location, &path)?;
    //     Ok(data)
    // }

    // fn write_cert(&mut self, location: Location, id: u128, data: Message) -> Result<()> {
    //     let path = self.cert_path(id);
    //     store::store(self.store, location, &path, &data)
    // }
}
