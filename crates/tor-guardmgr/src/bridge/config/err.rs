//! Error when parsing a bridge line from a string
//
// This module is included even if we don't have bridge support enabled,
// but all but one of the error variants are suppressed, making the error a unit enum.

use thiserror::Error;

/// Error when parsing a bridge line from a string
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub enum BridgeParseError {
    /// Bridge line was empty
    #[error("Bridge line was empty")]
    Empty,

    /// Expected PT name or host:port, looked a bit like a PT name, but didn't parse
    #[error(
        "Cannot parse {word:?} as PT name ({pt_error}), nor as direct bridge IpAddress:ORPort"
    )]
    InvalidPtOrAddr {
        /// The offending word
        word: String,
        /// Why we couldn't parse it as a PT name
        pt_error: tor_linkspec::TransportIdError,
    },

    /// Expected PT name or host:port, looked a bit like a host:port, but didn't parse
    #[error(
        "Cannot parse {word:?} as direct bridge IpAddress:ORPort ({addr_error}), nor as PT name"
    )]
    InvalidIpAddrOrPt {
        /// The offending word
        word: String,
        /// Why we couldn't parse it as an IP address and port
        addr_error: std::net::AddrParseError,
    },

    /// Cannot parse pluggable transport host address
    #[cfg(feature = "pt-client")]
    #[error("Cannot parse {word:?} as pluggable transport Host:ORPort")]
    InvalidIPtHostAddr {
        /// The offending word
        word: String,
        /// Why we couldn't parse it as a PT target Host:ORPort
        #[source]
        source: tor_linkspec::BridgeAddrError,
    },

    /// Cannot parse value as identity key, or PT key=value
    #[error("Cannot parse {word:?} as identity key ({id_error}), or PT key=value")]
    InvalidIdentityOrParameter {
        /// The offending word
        word: String,
        /// Why we couldn't parse it as a fingerprint
        id_error: tor_linkspec::RelayIdError,
    },

    /// PT key=value parameter does not contain an equals sign
    #[cfg(feature = "pt-client")]
    #[error("Expected PT key=value parameter, found {word:?} (which lacks an equals sign)")]
    InvalidPtKeyValue {
        /// The offending word
        word: String,
    },

    /// Invalid pluggable transport setting syntax
    #[cfg(feature = "pt-client")]
    #[error("Cannot parse {word:?} as a PT key=value parameter")]
    InvalidPluggableTransportSetting {
        /// The offending word
        word: String,
        /// Why we couldn't parse it
        #[source]
        source: tor_linkspec::PtTargetInvalidSetting,
    },

    /// More than one identity of the same type specified
    #[error("More than one identity of the same type specified, at {word:?}")]
    MultipleIdentitiesOfSameType {
        /// The offending word
        word: String,
    },

    /// Identity specified of unsupported type
    #[error("Identity specified but not of supported type, at {word:?}")]
    UnsupportedIdentityType {
        /// The offending word
        word: String,
    },

    /// Parameters may only be specified with a pluggable transport
    #[error("Parameters supplied but not valid without a pluggable transport")]
    DirectParametersNotAllowed,

    /// Every bridge must have an RSA identity
    #[error("Bridge line lacks specification of RSA identity key")]
    NoRsaIdentity,

    /// Pluggable transport support disabled in cargo features
    // We deliberately make this one *not* configured out if PT support is enabled
    #[error("Pluggable transport requested ({word:?} is not an IpAddress:ORPort), but support disabled in cargo features")]
    PluggableTransportsNotSupported {
        /// The offending word
        word: String,
    },
}
