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
use jwks_router_plugin::plugins::jwk_adapter::Claims;
use jsonwebtoken::{decode, decode_header, DecodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// use crate::plugins::error::JwtValidationError;
// use crate::plugins::jwk_adapter::{Claims, JwkAdapter};
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, PublicKeyUse, RSAKeyParameters,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey};
use openssl::bn::BigNumRef;
use openssl::pkey::Private;
use openssl::rsa::Rsa;

pub fn create_rsa_key() -> Rsa<Private> {
    Rsa::generate(2048).unwrap()
}

fn base64_encode_rsa(big_num_ref: &BigNumRef) -> String {
    let hex_val = big_num_ref.to_hex_str().unwrap().to_string();
    let bytes = hex::decode(hex_val).unwrap();
    base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
}

pub fn create_jwk_set(rsa: &Rsa<Private>, kid: String) -> JwkSet {
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

pub fn create_token(rsa: &Rsa<Private>, claims: Claims, kid: Option<String>) -> String {
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
