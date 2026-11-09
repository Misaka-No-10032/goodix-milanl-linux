use std::{fmt, io};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Protocol(&'static str),
    Device(&'static str),
    Enclave(&'static str),
    Template(&'static str),
    Cleanup(Box<Error>),
    Cancelled,
    Suspended,
    Shutdown,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O: {error}"),
            Self::Protocol(message) => write!(f, "protocol: {message}"),
            Self::Device(message) => write!(f, "sensor: {message}"),
            Self::Enclave(message) => write!(f, "enclave: {message}"),
            Self::Template(message) => write!(f, "template: {message}"),
            Self::Cleanup(error) => write!(f, "cleanup failed: {error}"),
            Self::Cancelled => f.write_str("client disconnected"),
            Self::Suspended => f.write_str("suspend requested"),
            Self::Shutdown => f.write_str("shutdown requested"),
        }
    }
}

impl std::error::Error for Error {}
