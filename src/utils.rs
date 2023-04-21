use littlefs2::path::PathBuf;

use crate::{
    syscall, try_syscall,
    types::{Location, Message, UserAttribute},
    Client, Error,
};

/// Write a large file (can be larger than 1KiB)
///
/// This is a wrapper around the [chunked writes api](crate::client::FilesystemClient::start_chunked_write)
pub fn write_all(
    client: &mut impl Client,
    location: Location,
    path: PathBuf,
    data: &[u8],
    user_attribute: Option<UserAttribute>,
) -> Result<(), Error> {
    if let Ok(msg) = Message::from_slice(data) {
        // Fast path for small files
        try_syscall!(client.write_file(location, path, msg, user_attribute))?;
        Ok(())
    } else {
        write_chunked(client, location, path, data, user_attribute)
    }
}

fn write_chunked(
    client: &mut impl Client,
    location: Location,
    path: PathBuf,
    data: &[u8],
    user_attribute: Option<UserAttribute>,
) -> Result<(), Error> {
    let res = write_chunked_inner(client, location, path, data, user_attribute);
    if res.is_err() {
        syscall!(client.abort_chunked_write());
        return res;
    }
    Ok(())
}

fn write_chunked_inner(
    client: &mut impl Client,
    location: Location,
    path: PathBuf,
    data: &[u8],
    user_attribute: Option<UserAttribute>,
) -> Result<(), Error> {
    let msg = Message::new();
    let chunk_size = msg.capacity();
    let chunks = data.chunks(chunk_size).map(|chunk| {
        Message::from(
            heapless::Vec::try_from(chunk)
                .expect("Iteration over chunks yields maximum of chunk_size"),
        )
    });
    try_syscall!(client.start_chunked_write(location, path, user_attribute))?;
    let mut written = 0;
    for chunk in chunks {
        written += chunk.len();
        try_syscall!(client.write_file_chunk(chunk))?;
    }

    if { written % chunk_size } == 0 {
        try_syscall!(client.write_file_chunk(Message::new()))?;
    }
    Ok(())
}
