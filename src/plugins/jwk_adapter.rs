use crate::plugins::error::JwtValidationError;
use anyhow::anyhow;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{decode, decode_header, DecodingKey, Header, TokenData, Validation};
use std::collections::HashMap;

pub struct JwkAdapter {}

impl JwkAdapter {
    /// Parses the JWT header value and returns it as string; returns an
    /// error if the JWT is invalid.
    pub fn parse_jwt_value(
        token_prefix: &String,
        jwt_value: &str,
    ) -> Result<String, anyhow::Error> {
        // Make sure the format of our message matches our expectations
        // Technically, the spec is case sensitive, but let's accept
        // case variations
        // this also adds the required space at the end for the token prefix
        // adding a new variable is used for splitting, however the initial prefix should be preserved for skipping empty string
        // prefixes
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

    pub fn validate(
        jwt: &str,
        jwks: &JwkSet,
    ) -> Result<TokenData<HashMap<String, serde_json::Value>>, JwtValidationError> {
        let jwt_head: Header = decode_header(jwt)?;

        // FIXME: do this inline
        let kid = match jwt_head.kid {
            Some(k) => k,
            None => return Err(JwtValidationError::MissingKid {}),
        };

        let token_result;
        let jwk = jwks.find(&kid).ok_or(JwtValidationError::UnknownKid(kid))?;

        match jwk.algorithm {
            AlgorithmParameters::RSA(ref rsa) => {
                // set up the decoding key for the JWT from the JWK
                let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e).unwrap();
                let validation = Validation::new(jwk.common.algorithm.unwrap());

                // attempt to decode
                token_result =
                    decode::<HashMap<String, serde_json::Value>>(jwt, &decoding_key, &validation);
            }
            _ => return Err(JwtValidationError::UnsupportedAlgorithm(jwt_head.alg)),
        }

        return match token_result {
            Ok(token) => Ok(token),
            Err(e) => {
                tracing::warn!("JWT validation error: {}", e);
                return Err(JwtValidationError::InvalidToken { source: e }); // , backtrace: Backtrace::capture() })
            }
        };
    }
}
