//! Trussed platform implemented in software with RAM storage **FOR TESTING ONLY**
//!
//! The random number generator in this module uses a
//! constant seed for test reproducability and by consequence is **not secure**

mod store;
mod ui;

use std::{
    fmt::Debug,
    marker::PhantomData,
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};

use chacha20::ChaCha8Rng;
use interchange::Interchange;
use rand_core::SeedableRng as _;

use crate::{platform, service::Service, types::Backends, ClientImplementation};

pub use store::{Filesystem, Ram, StoreProvider};
pub use ui::UserInterface;

pub type Client<'a, S> = ClientImplementation<'a, (), Service<'a, Platform<S>, (), 1>>;

// We need this mutex to make sure that the Store is not used concurrently
static MUTEX: Mutex<()> = Mutex::new(());

pub fn with_platform<S, R, F>(store: S, f: F) -> R
where
    S: StoreProvider,
    F: FnOnce(Platform<S>) -> R,
{
    f(Platform::new(store))
}

pub fn with_client<S, R, F>(store: S, client_id: &str, f: F) -> R
where
    S: StoreProvider,
    F: FnOnce(Client<'_, S>) -> R,
{
    Platform::new(store).run_client(client_id, (), f)
}

pub fn with_fs_client<P, R, F>(internal: P, client_id: &str, f: F) -> R
where
    P: Into<PathBuf>,
    F: FnOnce(Client<'_, Filesystem>) -> R,
{
    Platform::new(Filesystem::new(internal)).run_client(client_id, (), f)
}

pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(Client<'_, Ram>) -> R,
{
    Platform::new(Ram::default()).run_client(client_id, (), f)
}

pub struct Platform<S: StoreProvider, B = ()> {
    rng: ChaCha8Rng,
    _store: S,
    ui: UserInterface,
    _guard: MutexGuard<'static, ()>,
    _marker: PhantomData<B>,
}

impl<S: StoreProvider, B: 'static + Debug + PartialEq> Platform<S, B> {
    pub fn new(store: S) -> Self {
        let _guard = MUTEX.lock().unwrap_or_else(|err| err.into_inner());
        unsafe {
            store.reset();
        }
        // causing a regression again
        // let rng = chacha20::ChaCha8Rng::from_rng(rand_core::OsRng).unwrap();
        Self {
            rng: ChaCha8Rng::from_seed([42u8; 32]),
            _store: store,
            ui: UserInterface::new(),
            _guard,
            _marker: Default::default(),
        }
    }

    pub fn run_client<R, Bs, F>(self, client_id: &str, backends: Bs, test: F) -> R
    where
        Bs: Backends<Self>,
        F: for<'a> FnOnce(ClientImplementation<'a, B, Service<'a, Self, Bs, 1>>) -> R,
    {
        let interchange = Interchange::new();
        let service = Service::with_backends(self, &interchange, backends);
        let client = service.try_into_new_client(client_id).unwrap();
        test(client)
    }
}

unsafe impl<S: StoreProvider, B: 'static + Debug + PartialEq> platform::Platform
    for Platform<S, B>
{
    type B = B;
    type R = ChaCha8Rng;
    type S = S::Store;
    type UI = UserInterface;

    fn user_interface(&mut self) -> &mut Self::UI {
        &mut self.ui
    }

    fn rng(&mut self) -> &mut Self::R {
        &mut self.rng
    }

    fn store(&self) -> Self::S {
        unsafe { S::store() }
    }
}
