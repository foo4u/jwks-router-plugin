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
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, PublicKeyUse, RSAKeyParameters,
};
use jsonwebtoken::Algorithm;
use openssl::bn::BigNumRef;
use openssl::pkey::Private;
use openssl::rsa::Rsa;

pub trait JwkProvider<T> {
    fn create_key(&self) -> T;
    fn create_jwk(&self, kid: String) -> Jwk;
    fn create_jwk_set(&self, kid: String) -> JwkSet {
        JwkSet {
            keys: vec![self.create_jwk(kid)],
        }
    }
}

pub struct JwkBuilder {}

fn create_rsa_provider() -> impl JwkProvider<Rsa<Private>> {
    JwkBuilder {}
}

pub fn create_rsa_key_set(kids: Vec<String>) -> JwkSet {
    let provider = create_rsa_provider();
    let keys = kids
        .iter()
        .map(|kid| provider.create_jwk(kid.to_string()))
        .collect::<Vec<Jwk>>();

    JwkSet { keys }
}

impl JwkBuilder {
    fn create_common_parameters(kid: String, algorithm: Algorithm) -> CommonParameters {
        CommonParameters {
            public_key_use: (Some(PublicKeyUse::Signature)),
            key_operations: None,
            algorithm: Some(algorithm),
            key_id: Some(kid),
            x509_url: None,
            x509_chain: None,
            x509_sha1_fingerprint: None,
            x509_sha256_fingerprint: None,
        }
    }
}

impl JwkProvider<Rsa<Private>> for JwkBuilder {
    fn create_key(&self) -> Rsa<Private> {
        Rsa::generate(2048).unwrap()
    }

    fn create_jwk(&self, kid: String) -> Jwk {
        let key = self.create_key();
        Jwk {
            common: JwkBuilder::create_common_parameters(kid, Algorithm::RS256),
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: Default::default(),
                n: base64_encode_rsa(key.n()),
                e: base64_encode_rsa(key.e()),
            }),
        }
    }
}

fn base64_encode_rsa(big_num_ref: &BigNumRef) -> String {
    let hex_val = big_num_ref.to_hex_str().unwrap().to_string();
    let bytes = hex::decode(hex_val).unwrap();
    base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
}
