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
use crate::plugins::error::JwtValidationError;
use anyhow::anyhow;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{decode, decode_header, DecodingKey, Header, TokenData, Validation};
use std::collections::HashMap;

pub struct JwkAdapter {}

impl JwkAdapter {
    /// Parses the JWT header value and returns it as string if valid; an error otherwise.
    pub fn parse_jwt_value(
        token_prefix: &String,
        jwt_value: &str,
    ) -> Result<String, anyhow::Error> {
        // Make sure the format of our message matches our expectations
        // Technically, the spec is case sensitive, but let's accept
        // case variations
        if !jwt_value
            .to_uppercase()
            .as_str()
            .starts_with(&format!("{} ", token_prefix).to_uppercase())
            && token_prefix.chars().count() > 0
        {
            return Err(anyhow!("Header is not correctly formatted"));
        }

        // We know we have a "space" if the charcount is > 0, since we checked above. Split our string other
        // in (at most 2) sections.
        let jwt_parts: Vec<&str> = jwt_value.splitn(2, ' ').collect();

        if jwt_parts.len() != 2 && token_prefix.chars().count() > 0 {
            return Err(anyhow!("Authorization header is not correctly formatted"));
        }

        // Trim off any trailing white space (not valid in BASE64 encoding)
        let jwt = jwt_parts[if token_prefix.chars().count() > 0 {
            1
        } else {
            0
        }]
        .trim_end();

        return Ok(jwt.to_string());
    }

    /// Validates the given JWT against the given jwk_set and returns the claims if valid;
    /// a JwtValidationError otherwise.
    pub fn validate(
        jwt: &str,
        jwk_set: &JwkSet,
    ) -> Result<TokenData<HashMap<String, serde_json::Value>>, JwtValidationError> {
        let jwt_head: Header = decode_header(jwt)?;
        let kid = jwt_head.kid.ok_or(JwtValidationError::MissingKid)?;
        let jwk = jwk_set.find(&kid).ok_or(JwtValidationError::UnknownKid(kid))?;
        let token_result;

        match jwk.algorithm {
            AlgorithmParameters::RSA(ref rsa) => {
                let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e).unwrap();
                let validation = Validation::new(jwk.common.algorithm.unwrap());
                token_result =
                    decode::<HashMap<String, serde_json::Value>>(jwt, &decoding_key, &validation);
            }
            _ => return Err(JwtValidationError::UnsupportedAlgorithm(jwt_head.alg)),
        }

        return match token_result {
            Ok(token) => Ok(token),
            Err(e) => {
                tracing::warn!("JWT validation error: {}", e);
                return Err(JwtValidationError::InvalidToken { source: e });
            }
        };
    }
}
