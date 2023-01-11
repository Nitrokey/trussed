#![cfg(feature = "virt")]

use trussed::{
    api::{reply::ReadFile, Reply, Request},
    client::{FilesystemClient as _, PollClient as _},
    error::Error,
    platform,
    service::{Service, ServiceResources},
    types::{self, ClientContext, Location, Message, PathBuf, ServiceBackend, ServiceBackends},
    virt::{self, Ram},
    ClientImplementation,
};

type Platform = virt::Platform<Ram, Backend>;
type Client<'a> = ClientImplementation<'a, Backend, Service<'a, Platform, Backends, 1>>;

const BACKENDS_TEST: &[ServiceBackends<Backend>] = &[
    ServiceBackends::Custom(Backend::Test),
    ServiceBackends::Software,
];

#[derive(Debug, PartialEq)]
pub enum Backend {
    Test,
}

#[derive(Default)]
struct Backends {
    test: TestBackend,
}

impl types::Backends<Platform> for Backends {
    fn select(&mut self, backend: &Backend) -> Option<&mut dyn ServiceBackend<Platform>> {
        match backend {
            Backend::Test => Some(&mut self.test),
        }
    }
}

#[derive(Default)]
struct TestBackend;

impl<P: platform::Platform> ServiceBackend<P> for TestBackend {
    fn reply_to(
        &mut self,
        _client_id: &mut ClientContext<P::B>,
        request: &Request<P::B>,
        _resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        match request {
            Request::ReadFile(_) => {
                let mut data = Message::new();
                data.push(0xff).unwrap();
                Ok(Reply::ReadFile(ReadFile { data }))
            }
            _ => Err(Error::RequestNotAvailable),
        }
    }
}

fn run<F: FnOnce(&mut Client<'_>)>(f: F) {
    Platform::new(Ram::default())
        .run_client("test", Backends::default(), |mut client| f(&mut client))
}

#[test]
fn override_syscall() {
    run(|client| {
        let path = PathBuf::from("test");
        assert!(trussed::try_syscall!(client.read_file(Location::Internal, path.clone())).is_err());

        trussed::syscall!(client.set_service_backends(BACKENDS_TEST));

        assert_eq!(
            trussed::syscall!(client.read_file(Location::Internal, path)).data,
            &[0xff]
        );
    })
}
