// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, fmt, io};

#[derive(Debug)]
pub enum ErrorKind {
    Io,
    Ebpf,
    Map,
    Program,
    TryFromSlice,
    Bug,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Io => f.write_str("Io"),
            ErrorKind::Ebpf => f.write_str("Ebpf"),
            ErrorKind::Map => f.write_str("Map"),
            ErrorKind::Program => f.write_str("Program"),
            ErrorKind::TryFromSlice => f.write_str("TryFromSlice"),
            ErrorKind::Bug => f.write_str("Bug"),
        }
    }
}

#[derive(Debug)]
pub struct EfenseError {
    pub kind: ErrorKind,
    pub msg: String,
}

impl fmt::Display for EfenseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.msg)
    }
}

fn format_error_chain<E: Error + ?Sized>(e: &E) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(inner) = src {
        s.push_str(": ");
        s.push_str(&inner.to_string());
        src = inner.source();
    }
    s
}

impl Error for EfenseError {}

impl From<io::Error> for EfenseError {
    fn from(e: io::Error) -> Self {
        EfenseError {
            kind: ErrorKind::Io,
            msg: e.to_string(),
        }
    }
}

impl From<aya::EbpfError> for EfenseError {
    fn from(e: aya::EbpfError) -> Self {
        EfenseError {
            kind: ErrorKind::Ebpf,
            msg: format_error_chain(&e),
        }
    }
}

impl From<aya::maps::MapError> for EfenseError {
    fn from(e: aya::maps::MapError) -> Self {
        EfenseError {
            kind: ErrorKind::Map,
            msg: format_error_chain(&e),
        }
    }
}

impl From<aya::programs::ProgramError> for EfenseError {
    fn from(e: aya::programs::ProgramError) -> Self {
        EfenseError {
            kind: ErrorKind::Program,
            msg: format_error_chain(&e),
        }
    }
}

impl From<aya::pin::PinError> for EfenseError {
    fn from(e: aya::pin::PinError) -> Self {
        EfenseError {
            kind: ErrorKind::Program,
            msg: format_error_chain(&e),
        }
    }
}

impl From<aya::programs::links::LinkError> for EfenseError {
    fn from(e: aya::programs::links::LinkError) -> Self {
        EfenseError {
            kind: ErrorKind::Program,
            msg: format_error_chain(&e),
        }
    }
}

impl From<std::array::TryFromSliceError> for EfenseError {
    fn from(e: std::array::TryFromSliceError) -> Self {
        EfenseError {
            kind: ErrorKind::TryFromSlice,
            msg: e.to_string(),
        }
    }
}

impl From<String> for EfenseError {
    fn from(e: String) -> Self {
        EfenseError {
            kind: ErrorKind::Bug,
            msg: e,
        }
    }
}

impl From<&str> for EfenseError {
    fn from(e: &str) -> Self {
        EfenseError {
            kind: ErrorKind::Bug,
            msg: e.to_string(),
        }
    }
}
