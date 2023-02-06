#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use littlefs2::consts;

// TODO: this needs to be overridable.
// Should we use the "config crate that can have a replacement patched in" idea?

pub type MAX_APPLICATION_NAME_LENGTH = consts::U256;
pub const MAX_LONG_DATA_LENGTH: usize = 1024;
pub const MAX_MESSAGE_LENGTH: usize = 1024;
pub type MAX_OBJECT_HANDLES = consts::U16;
pub type MAX_LABEL_LENGTH = consts::U256;
pub const MAX_MEDIUM_DATA_LENGTH: usize = 256;
pub type MAX_PATH_LENGTH = consts::U256;
cfg_if::cfg_if! {
    if #[cfg(feature = "clients-12")] {
        pub type MAX_SERVICE_CLIENTS = consts::U12;
    } else if #[cfg(feature = "clients-11")] {
        pub type MAX_SERVICE_CLIENTS = consts::U11;
    } else if #[cfg(feature = "clients-10")] {
        pub type MAX_SERVICE_CLIENTS = consts::U10;
    } else if #[cfg(feature = "clients-9")] {
        pub type MAX_SERVICE_CLIENTS = consts::U9;
    } else if #[cfg(feature = "clients-8")] {
        pub type MAX_SERVICE_CLIENTS = consts::U8;
    } else if #[cfg(feature = "clients-7")] {
        pub type MAX_SERVICE_CLIENTS = consts::U7;
    } else if #[cfg(feature = "clients-6")] {
        pub type MAX_SERVICE_CLIENTS = consts::U6;
    } else if #[cfg(feature = "clients-5")] {
        pub type MAX_SERVICE_CLIENTS = consts::U5;
    } else if #[cfg(feature = "clients-4")] {
        pub type MAX_SERVICE_CLIENTS = consts::U4;
    } else if #[cfg(feature = "clients-3")] {
        pub type MAX_SERVICE_CLIENTS = consts::U3;
    } else if #[cfg(feature = "clients-2")] {
        pub type MAX_SERVICE_CLIENTS = consts::U2;
    } else if #[cfg(feature = "clients-1")] {
        pub type MAX_SERVICE_CLIENTS = consts::U1;
    }
}
pub const MAX_SHORT_DATA_LENGTH: usize = 128;

pub const MAX_SIGNATURE_LENGTH: usize = 512 * 2;
// FIXME: Value from https://stackoverflow.com/questions/5403808/private-key-length-bytes for Rsa2048 Private key
pub const MAX_KEY_MATERIAL_LENGTH: usize = 1160 * 2 + 72;

// must be MAX_KEY_MATERIAL_LENGTH + 4
pub const MAX_SERIALIZED_KEY_LENGTH: usize = MAX_KEY_MATERIAL_LENGTH + 4;

pub const MAX_USER_ATTRIBUTE_LENGTH: usize = 256;

pub const USER_ATTRIBUTE_NUMBER: u8 = 37;

// request size is chosen to not exceed the largest standard syscall, Decrypt, so that the Request
// enum does not grow from this variant
pub const SERDE_EXTENSION_REQUEST_LENGTH: usize =
    2 * MAX_MESSAGE_LENGTH + 2 * MAX_SHORT_DATA_LENGTH;
// reply size is chosen to not exceed the largest standard syscall, Encrypt, so that the Reply enum
// does not grow from this variant
pub const SERDE_EXTENSION_REPLY_LENGTH: usize = MAX_MESSAGE_LENGTH + 2 * MAX_SHORT_DATA_LENGTH;
