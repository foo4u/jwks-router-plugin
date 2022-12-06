/*
 * (C) Copyright 2022 Scott Rossillo and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
use jsonwebtoken::Algorithm;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtValidationError {
    #[error("JWT header missing a kid")]
    MissingKid,
    #[error("JWT error: {source}")]
    InvalidToken {
        #[from]
        source: jsonwebtoken::errors::Error,
    },
    #[error("Authorization is not a valid JWT")]
    InvalidTokenFormat,
    #[error("Authorization header is not correctly formatted")]
    InvalidTokenHeader,
    #[error("Missing required claim: {0}")]
    MissingClaim(String),
    #[error("JWT kid {0} not found in JWK set")]
    UnknownKid(String),
    #[error("Unsupported JWT algorithm")]
    UnsupportedAlgorithm(Algorithm),
}
