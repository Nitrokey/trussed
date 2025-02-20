pub use generic_array::GenericArray;

pub use heapless::{String, Vec};

pub use crate::Bytes;

pub use littlefs2::{driver::Storage as LfsStorage, fs::Filesystem};
pub use littlefs2_core::{DirEntry, Metadata, Path, PathBuf, Result as LfsResult};

pub use trussed_core::types::{
    reboot, CertId, CounterId, Id, KeyId, KeySerialization, Location, Mechanism, MediumData,
    Message, ObjectId, SerializedKey, ShortData, Signature, SignatureSerialization, SpecialId,
    StorageAttributes, UserAttribute,
};

use crate::interrupt::InterruptFlag;
use crate::store::filestore::{ReadDirFilesState, ReadDirState};

pub use crate::client::FutureResult;
pub use crate::platform::Platform;

/// An empty struct not storing any data.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NoData;

pub mod ui {
    use serde::{Deserialize, Serialize};

    // TODO: Consider whether a simple "language" to specify "patterns"
    // makes sense, vs. "semantic" indications with platform-specific implementation
    #[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum Status {
        Idle,
        WaitingForUserPresence,
        Processing,
        Error,
        Custom(u8),
    }
}

pub mod consent {
    pub use trussed_core::types::consent::{Error, Level, Result};

    use serde::{Deserialize, Serialize};

    #[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub enum Urgency {
        /// Pending other user consent requests will fail as interrupted.
        InterruptOthers,
        /// If other user consent requests are pending, fail this request.
        FailIfOthers,
    }
}

/// The context for a syscall (per client).
///
/// The context stores the state used by the standard syscall implementations, see
/// [`CoreContext`][].  Additionally, backends can define a custom context for their syscall
/// implementations.
#[non_exhaustive]
pub struct Context<B> {
    pub core: CoreContext,
    pub backends: B,
}

impl<B: Default> From<CoreContext> for Context<B> {
    fn from(core: CoreContext) -> Self {
        Self {
            core,
            backends: B::default(),
        }
    }
}

// The "CoreContext" struct is the closest equivalent to a PCB that Trussed
// currently has. Trussed currently uses it to choose the client-specific
// subtree in the filesystem (see docs in src/store.rs) and to maintain
// the walker state of the directory traversal syscalls.
#[non_exhaustive]
pub struct CoreContext {
    pub path: PathBuf,
    pub read_dir_state: Option<ReadDirState>,
    pub read_dir_files_state: Option<ReadDirFilesState>,
    pub interrupt: Option<&'static InterruptFlag>,
}

impl CoreContext {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            read_dir_state: None,
            read_dir_files_state: None,
            interrupt: None,
        }
    }

    pub fn with_interrupt(path: PathBuf, interrupt: Option<&'static InterruptFlag>) -> Self {
        Self {
            path,
            read_dir_state: None,
            read_dir_files_state: None,
            interrupt,
        }
    }
}

impl From<PathBuf> for CoreContext {
    fn from(path: PathBuf) -> Self {
        Self::new(path)
    }
}

impl From<&str> for CoreContext {
    fn from(s: &str) -> Self {
        Self::new(s.try_into().unwrap())
    }
}

// Object Hierarchy according to Cryptoki
// - Storage
//   - Domain parameters
//   - Key
//   - Certificate
//   - Data
// - Hardware feature
// - Mechanism
// - Profiles

impl Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_be_bytes())
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValueVisitor<'de>(PhantomData<&'de ()>);

        impl<'de> serde::de::Visitor<'de> for ValueVisitor<'de> {
            type Value = Id;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("16 bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 16 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                Ok(Id(u128::from_be_bytes(v.try_into().unwrap())))
            }
        }

        deserializer.deserialize_bytes(ValueVisitor(PhantomData))
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Location {
    Volatile,
    Internal,
    External,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StorageAttributes {
    // each object must have a unique ID
    // unique_id: UniqueId,

    // description of object
    // label: String<MAX_LABEL_LENGTH>,

    // // cryptoki: token (vs session) object
    // persistent: bool,
    pub persistence: Location,

    /// Wether a the result of an [`agree`](crate::client::CryptoClient::agree) can be serialized
    /// with [`serialize_key`](crate::client::CryptoClient::serialize_key)
    pub serializable: bool,
    // cryptoki: user must be logged in
    // private: bool,

    // modifiable: bool,
    // copyable: bool,
    // destroyable: bool,
}

impl StorageAttributes {
    pub fn set_persistence(mut self, persistence: Location) -> Self {
        self.persistence = persistence;
        self
    }

    pub fn set_serializable(mut self, serializable: bool) -> Self {
        self.serializable = serializable;
        self
    }
}

impl StorageAttributes {
    // pub fn new(unique_id: UniqueId) -> Self {
    pub fn new() -> Self {
        Self {
            // unique_id,
            // label: String::new(),
            // persistent: false,
            persistence: Location::Volatile,
            serializable: false,
            // modifiable: true,
            // copyable: true,
            // destroyable: true,
        }
    }
}

impl Default for StorageAttributes {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Mechanism {
    Aes256Cbc,
    Chacha8Poly1305,
    Ed255,
    HmacBlake2s,
    HmacSha1,
    HmacSha256,
    HmacSha512,
    // P256XSha256,
    P256,
    P256Prehashed,
    P384,
    P384Prehashed,
    P521,
    P521Prehashed,
    BrainpoolP256R1,
    BrainpoolP256R1Prehashed,
    BrainpoolP384R1,
    BrainpoolP384R1Prehashed,
    BrainpoolP512R1,
    BrainpoolP512R1Prehashed,
    // clients can also do hashing by themselves
    Sha256,
    Tdes,
    Totp,
    Trng,
    X255,
    /// Used to serialize the output of a diffie-hellman
    SharedSecret,

    /// Exposes the Raw RSA encryption/decryption primitive. Be aware this is dangerous.
    /// Not having any padding can allow an attacker to obtain plaintexts and forge signatures.
    /// It should only be used if absolutely necessary.
    Rsa2048Raw,
    /// Exposes the Raw RSA encryption/decryption primitive. Be aware this is dangerous.
    /// Not having any padding can allow an attacker to obtain plaintexts and forge signatures.
    /// It should only be used if absolutely necessary.
    Rsa3072Raw,
    /// Exposes the Raw RSA encryption/decryption primitive. Be aware this is dangerous.
    /// Not having any padding can allow an attacker to obtain plaintexts and forge signatures.
    /// It should only be used if absolutely necessary.
    Rsa4096Raw,

    Rsa2048Pkcs1v15,
    Rsa3072Pkcs1v15,
    Rsa4096Pkcs1v15,

    // Post-quantum cryptography algorithms
    #[cfg(feature = "backend-dilithium2")]
    Dilithium2,
    #[cfg(feature = "backend-dilithium3")]
    Dilithium3,
    #[cfg(feature = "backend-dilithium5")]
    Dilithium5,
}

pub type MediumData = Bytes<MAX_MEDIUM_DATA_LENGTH>;
pub type ShortData = Bytes<MAX_SHORT_DATA_LENGTH>;

pub type Message = Bytes<MAX_MESSAGE_LENGTH>;
pub type SerializedKey = Bytes<MAX_SERIALIZED_KEY_LENGTH>;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum KeySerialization {
    // Asn1Der,
    Cose,
    // Der,
    EcdhEsHkdf256,
    Raw,
    Sec1,
    /// Used by backends implementing RSA.
    ///
    /// Since RSA keys have multiple parts, and that the [`SerializeKey`](crate::api::Reply::SerializeKey) and
    /// [`UnsafeInjectKey`](crate::api::Request::UnsafeInjectKey) have only transfer one byte array, the RSA key is serialized with postcard
    RsaParts,
    Pkcs8Der,
}

pub type Signature = Bytes<MAX_SIGNATURE_LENGTH>;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum SignatureSerialization {
    Asn1Der,
    // Cose,
    Raw,
    // Sec1,
}

pub type UserAttribute = Bytes<MAX_USER_ATTRIBUTE_LENGTH>;
