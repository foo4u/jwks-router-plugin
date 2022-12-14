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
    AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters, Jwk, JwkSet,
    PublicKeyUse, RSAKeyParameters,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use jwks_router_plugin::plugins::jwt_adapter::Claims;
use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::rsa::Rsa;

/// Returns a base64 encoded string of the given big number in hex format.
fn base64_encode_hex(big_num_ref: &BigNumRef) -> String {
    let hex_val = big_num_ref.to_hex_str().unwrap().to_string();
    let bytes = hex::decode(hex_val).unwrap();
    base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
}

pub trait JwkProvider<T> {
    fn create_key(&self) -> T;
    fn create_jwk(&self, kid: String) -> Jwk {
        let k = self.create_key();
        self.create_jwk_from_key(k, kid)
    }
    fn create_jwk_from_key(&self, key: T, kid: String) -> Jwk;
    fn create_jwk_set(&self, kid: String) -> JwkSet {
        JwkSet {
            keys: vec![self.create_jwk(kid)],
        }
    }
    fn create_token(&self, key: &T, claims: Claims, kid: Option<String>) -> String;
}

pub struct JwkBuilder {}

// FIXME: this is actually used
#[allow(dead_code)]
pub fn create_rsa_provider() -> impl JwkProvider<Rsa<Private>> {
    JwkBuilder {}
}

// FIXME: this is actually used
#[allow(dead_code)]
pub fn create_ecdsa_provider() -> impl JwkProvider<EcKey<Private>> {
    JwkBuilder {}
}

// FIXME: this is actually used
#[allow(dead_code)]
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

    fn create_jwk_from_key(&self, key: Rsa<Private>, kid: String) -> Jwk {
        Jwk {
            common: JwkBuilder::create_common_parameters(kid, Algorithm::RS256),
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: Default::default(),
                n: base64_encode_hex(key.n()),
                e: base64_encode_hex(key.e()),
            }),
        }
    }

    fn create_token(&self, rsa: &Rsa<Private>, claims: Claims, kid: Option<String>) -> String {
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
}

impl JwkProvider<EcKey<Private>> for JwkBuilder {
    fn create_key(&self) -> EcKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        EcKey::generate(&group).unwrap()
    }

    fn create_jwk_from_key(&self, key: EcKey<Private>, kid: String) -> Jwk {
        let mut x: BigNum = BigNum::new().unwrap();
        let mut y: BigNum = BigNum::new().unwrap();
        let mut ctx: BigNumContext = BigNumContext::new().unwrap();
        key.public_key()
            .affine_coordinates(key.group(), &mut x, &mut y, &mut ctx)
            .expect("Expected key to emit x and y");
        Jwk {
            common: JwkBuilder::create_common_parameters(kid, Algorithm::ES256),
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: Default::default(),
                curve: EllipticCurve::P256,
                x: base64_encode_hex(&x),
                y: base64_encode_hex(&y),
            }),
        }
    }

    fn create_token(&self, key: &EcKey<Private>, claims: Claims, kid: Option<String>) -> String {
        let mut header = Header::new(Algorithm::ES256);
        let private_key = key.private_key_to_pem().unwrap();
        let encoding_key = EncodingKey::from_ec_pem(&private_key).unwrap();
        header.kid = kid;
        encode(&header, &claims, &encoding_key).unwrap()
    }
}
