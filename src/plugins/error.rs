use thiserror::Error;
use jsonwebtoken::Algorithm;

#[derive(Error, Debug)]
pub enum JwtValidationError {
    #[error("JWT header missing a kid")]
    MissingKid,
    #[error("Invalid JWT {source}")]
    InvalidToken {
        #[from]
        source: jsonwebtoken::errors::Error, // backtrace: Backtrace
    },
    #[error("JWT kid {0} not found in JWK set")]
    UnknownKid(String),
    #[error("Unsupported JWT algorithm")]
    UnsupportedAlgorithm(Algorithm),
}
