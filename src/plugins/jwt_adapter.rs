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
#![deny(clippy::unwrap_used)]
use crate::plugins::error::JwtValidationError;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, DecodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    pub iat: usize, // Optional. Issued at (as UTC timestamp)
    pub iss: String, // Optional. Issuer
}

pub struct JwtAdapter {}

impl JwtAdapter {
    /// Parses the JWT header value and returns it as string if valid; an error otherwise.
    pub fn parse_jwt_value(
        token_prefix: &String,
        jwt_value: &str,
    ) -> Result<String, JwtValidationError> {
        if !jwt_value
            .to_uppercase()
            .as_str()
            .starts_with(&format!("{} ", token_prefix).to_uppercase())
            && token_prefix.chars().count() > 0
        {
            return Err(JwtValidationError::InvalidTokenHeader);
        }

        let jwt_parts: Vec<&str> = jwt_value.splitn(2, ' ').collect();

        if jwt_parts.len() != 2 && token_prefix.chars().count() > 0 {
            return Err(JwtValidationError::InvalidTokenFormat);
        }

        // Trim off any trailng white space (not valid in BASE64 encoding)
        let jwt = jwt_parts[1].trim_end();

        Ok(jwt.to_string())
    }

    fn decoding_key(jwk: &Jwk) -> Result<DecodingKey, JwtValidationError> {
        match jwk.algorithm {
            AlgorithmParameters::RSA(ref rsa) => {
                Ok(DecodingKey::from_rsa_components(&rsa.n, &rsa.e)?)
            }
            AlgorithmParameters::EllipticCurve(ref ec) => {
                Ok(DecodingKey::from_ec_components(&ec.x, &ec.y)?)
            }
            _ => {
                let alg = jwk
                    .common
                    .algorithm
                    .ok_or_else(|| JwtValidationError::MissingClaim("alg".to_string()))?;
                Err(JwtValidationError::UnsupportedAlgorithm(alg))
            }
        }
    }

    /// Validates the given JWT against the given jwk_set and returns the claims if valid;
    /// a JwtValidationError otherwise.
    pub fn validate(
        jwt: &str,
        jwk_set: &JwkSet,
        issuer: &Option<String>,
    ) -> Result<TokenData<Claims>, JwtValidationError> {
        let jwt_head: Header = decode_header(jwt)?;
        let kid = jwt_head.kid.ok_or(JwtValidationError::MissingKid)?;
        let jwk = jwk_set
            .find(&kid)
            .ok_or(JwtValidationError::UnknownKid(kid))?;
        let alg = jwk
            .common
            .algorithm
            .ok_or_else(|| JwtValidationError::MissingClaim("alg".to_string()))?;
        let decoding_key = Self::decoding_key(jwk)?;
        let mut validation = Validation::new(alg);

        if let Some(iss) = issuer {
            validation.set_issuer(&[iss])
        }

        let token_result = decode::<Claims>(jwt, &decoding_key, &validation);

        match token_result {
            Ok(token) => Ok(token),
            Err(e) => {
                tracing::warn!("JWT validation error: {}", e);
                Err(JwtValidationError::InvalidToken { source: e })
            }
        }
    }
}
