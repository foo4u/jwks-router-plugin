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
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, DecodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    pub iat: usize, // Optional. Issued at (as UTC timestamp)
    pub iss: String, // Optional. Issuer
    pub nbf: usize, // Optional. Not Before (as UTC timestamp)
}

pub struct JwkAdapter {}

impl JwkAdapter {
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

        // Trim off any trailing white space (not valid in BASE64 encoding)
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

#[cfg(test)]
mod tests {
    use crate::plugins::error::JwtValidationError;
    use crate::plugins::jwk_adapter::{Claims, JwkAdapter};
    use jsonwebtoken::jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurveKeyParameters, Jwk, JwkSet,
        PublicKeyUse, RSAKeyParameters,
    };
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use openssl::bn::BigNumRef;
    use openssl::ec::{EcGroup, EcGroupRef, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::Private;
    use openssl::rsa::Rsa;

    fn create_rsa_key() -> Rsa<Private> {
        Rsa::generate(2048).unwrap()
    }

    fn create_ecdsa_key() -> EcKey<Private> {
        let group = EcGroup::from_curve_name(Nid::ECDSA_WITH_SHA256).unwrap();
        return EcKey::generate(&group).unwrap();
    }

    fn base64_encode_rsa(big_num_ref: &BigNumRef) -> String {
        let hex_val = big_num_ref.to_hex_str().unwrap().to_string();
        let bytes = hex::decode(hex_val).unwrap();
        base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
    }

    fn create_jwk_set(rsa: &Rsa<Private>, kid: String) -> JwkSet {
        let key = Jwk {
            common: CommonParameters {
                public_key_use: (Some(PublicKeyUse::Signature)),
                key_operations: None,
                algorithm: Some(Algorithm::RS256),
                key_id: Some(kid),
                x509_url: None,
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: Default::default(),
                n: base64_encode_rsa(rsa.n()),
                e: base64_encode_rsa(rsa.e()),
            }),
        };
        JwkSet { keys: vec![key] }
    }

    fn valid_claims() -> Claims {
        Claims {
            iat: chrono::Local::now().timestamp() as usize,
            exp: chrono::Local::now().timestamp() as usize + 5000,
            iss: "https://issuer.example.com".to_owned(),
            nbf: chrono::Local::now().timestamp() as usize - 5000,
        }
    }

    fn expired_claims() -> Claims {
        Claims {
            iat: chrono::Local::now().timestamp() as usize - 50_000,
            exp: chrono::Local::now().timestamp() as usize - 5000,
            iss: "https://issuer.example.com".to_owned(),
            nbf: chrono::Local::now().timestamp() as usize - 50_000,
        }
    }

    fn create_token(rsa: &Rsa<Private>, claims: Claims, kid: Option<String>) -> String {
        let mut header = Header::new(Algorithm::RS256);
        let private_key = rsa.private_key_to_pem().unwrap();
        header.kid = kid;
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(&private_key).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn validate_rsa_jwt() {
        let rsa = create_rsa_key();
        let kid = "our_id".to_string();
        let token = create_token(&rsa, valid_claims(), Some(kid.clone()));

        let jwk_set = create_jwk_set(&rsa, kid);

        assert!(JwkAdapter::validate(token.as_str(), &jwk_set, &None).is_ok());
    }

    #[test]
    fn validate_jwt_invalid_issuer() -> Result<(), String> {
        let rsa = create_rsa_key();
        let kid = "our_id".to_string();
        let token = create_token(&rsa, valid_claims(), Some(kid.clone()));

        let jwk_set = create_jwk_set(&rsa, kid);

        match JwkAdapter::validate(
            token.as_str(),
            &jwk_set,
            &Some("https://spoofed.example.com/".to_string()),
        ) {
            Ok(_) => Err("expected validation to fail".to_string()),
            Err(e) => match e {
                JwtValidationError::InvalidToken { .. } => Ok(()),
                _ => Err("expected invalid token error".to_string()),
            },
        }
    }

    #[test]
    fn validate_jwt_kid_missing_id() -> Result<(), String> {
        let rsa = create_rsa_key();
        let kid = "our_id".to_string();
        let token = create_token(&rsa, valid_claims(), None);

        let jwk_set = create_jwk_set(&rsa, kid.to_string());

        match JwkAdapter::validate(token.as_str(), &jwk_set, &None) {
            Ok(_) => Err("expected validation to fail".to_string()),
            Err(e) => match e {
                JwtValidationError::MissingKid { .. } => Ok(()),
                _ => Err("expected missing kid error".to_string()),
            },
        }
    }

    #[test]
    fn validate_jwt_kid_not_found() -> Result<(), String> {
        let rsa = create_rsa_key();
        let kid = "our_id".to_string();
        let token = create_token(&rsa, valid_claims(), Some(kid.clone()));

        let jwk_set = create_jwk_set(&rsa, "fake".to_string());

        match JwkAdapter::validate(token.as_str(), &jwk_set, &None) {
            Ok(_) => return Err("expected validation to fail".to_string()),
            Err(e) => match e {
                JwtValidationError::UnknownKid { .. } => Ok(()),
                _ => Err("expected unknown kid error".to_string()),
            },
        }
    }

    #[test]
    fn validate_jwt_expired() -> Result<(), String> {
        let rsa = create_rsa_key();
        let kid = "our_id".to_string();
        let token = create_token(&rsa, expired_claims(), Some(kid.clone()));

        let jwk_set = create_jwk_set(&rsa, kid);

        match JwkAdapter::validate(token.as_str(), &jwk_set, &None) {
            Ok(_) => return Err("expected validation to fail".to_string()),
            Err(e) => match e {
                JwtValidationError::InvalidToken { .. } => Ok(()),
                _ => Err("expected invalid token error".to_string()),
            },
        }
    }
}
