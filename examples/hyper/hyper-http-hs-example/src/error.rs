use std::fmt::{Display, Formatter};
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::{error, fmt, io, result};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InvalidVersion,
    NoAcceptableMethod,
    AddrUnsupported,
    CommandUnsupported,
    UsernameNotFound,
    InvalidPassword,
    Io(io::Error),
    Utf8(Utf8Error),
}

impl error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion => write!(f, "invalid protocol version"),
            Self::NoAcceptableMethod => write!(f, "no acceptable method"),
            Self::AddrUnsupported => write!(f, "address type unsupported"),
            Self::CommandUnsupported => write!(f, "command unsupported"),
            Self::UsernameNotFound => write!(f, "username not found"),
            Self::InvalidPassword => write!(f, "invalid password"),
            Self::Io(e) => e.fmt(f),
            Self::Utf8(e) => e.fmt(f),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<Utf8Error> for Error {
    fn from(e: Utf8Error) -> Self {
        Self::Utf8(e)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        Self::Utf8(e.utf8_error())
    }
}
