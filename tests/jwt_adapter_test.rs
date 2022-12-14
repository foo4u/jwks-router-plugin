mod fixtures;

use crate::fixtures::json_web_key_set::create_ecdsa_provider;
use fixtures::json_web_key_set::create_rsa_provider;
use fixtures::json_web_key_set::JwkProvider;
use jsonwebtoken::jwk::JwkSet;
use jwks_router_plugin::plugins::error::JwtValidationError;
use jwks_router_plugin::plugins::jwt_adapter::{Claims, JwtAdapter};

fn valid_claims() -> Claims {
    Claims {
        iat: chrono::Local::now().timestamp() as usize,
        exp: chrono::Local::now().timestamp() as usize + 5000,
        iss: "https://issuer.example.com".to_owned(),
    }
}

fn expired_claims() -> Claims {
    Claims {
        iat: chrono::Local::now().timestamp() as usize - 50_000,
        exp: chrono::Local::now().timestamp() as usize - 5000,
        iss: "https://issuer.example.com".to_owned(),
    }
}

#[test]
fn validate_rsa_jwt() {
    let kp = create_rsa_provider();
    let rsa = kp.create_key();
    let kid = "our_id".to_string();
    let token = kp.create_token(&rsa, valid_claims(), Some(kid.clone()));

    let jwk_set = JwkSet {
        keys: vec![kp.create_jwk_from_key(rsa, kid)],
    };

    assert!(JwtAdapter::validate(token.as_str(), &jwk_set, &None).is_ok());
}

#[ignore]
#[test]
fn validate_ecdsa_jwt() {
    let kp = create_ecdsa_provider();
    let ec_key = kp.create_key();
    let kid = "our_id".to_string();

    println!(
        "eckey in pem is: {:?}",
        &ec_key
            .private_key_to_pem()
            .expect(&*"Expected PEM key".to_string())
    );

    let token = kp.create_token(&ec_key, valid_claims(), Some(kid.clone()));

    let jwk_set = JwkSet {
        keys: vec![kp.create_jwk_from_key(ec_key, kid)],
    };

    assert!(JwtAdapter::validate(token.as_str(), &jwk_set, &None).is_ok());
}

#[test]
fn validate_jwt_invalid_issuer() -> Result<(), String> {
    let kp = create_rsa_provider();
    let rsa = kp.create_key();
    let kid = "our_id".to_string();
    let token = kp.create_token(&rsa, valid_claims(), Some(kid.clone()));

    let jwk_set = JwkSet {
        keys: vec![kp.create_jwk_from_key(rsa, kid)],
    };

    match JwtAdapter::validate(
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
    let kp = create_rsa_provider();
    let rsa = kp.create_key();
    let kid = "our_id".to_string();
    let token = kp.create_token(&rsa, valid_claims(), None);

    let jwk_set = JwkSet {
        keys: vec![kp.create_jwk_from_key(rsa, kid)],
    };

    match JwtAdapter::validate(token.as_str(), &jwk_set, &None) {
        Ok(_) => Err("expected validation to fail".to_string()),
        Err(e) => match e {
            JwtValidationError::MissingKid { .. } => Ok(()),
            _ => Err("expected missing kid error".to_string()),
        },
    }
}

#[test]
fn validate_jwt_kid_not_found() -> Result<(), String> {
    let kp = create_rsa_provider();
    let rsa = kp.create_key();
    let kid = "our_id".to_string();
    let token = kp.create_token(&rsa, valid_claims(), Some(kid.clone()));

    let jwk_set = JwkSet {
        keys: vec![kp.create_jwk_from_key(rsa, "fake".to_string())],
    };

    match JwtAdapter::validate(token.as_str(), &jwk_set, &None) {
        Ok(_) => return Err("expected validation to fail".to_string()),
        Err(e) => match e {
            JwtValidationError::UnknownKid { .. } => Ok(()),
            _ => Err("expected unknown kid error".to_string()),
        },
    }
}

#[test]
fn validate_jwt_expired() -> Result<(), String> {
    let kp = create_rsa_provider();
    let rsa = kp.create_key();
    let kid = "our_id".to_string();
    let token = kp.create_token(&rsa, expired_claims(), Some(kid.clone()));

    let jwk_set = JwkSet {
        keys: vec![kp.create_jwk_from_key(rsa, kid)],
    };

    match JwtAdapter::validate(token.as_str(), &jwk_set, &None) {
        Ok(_) => return Err("expected validation to fail".to_string()),
        Err(e) => match e {
            JwtValidationError::InvalidToken { .. } => Ok(()),
            _ => Err("expected invalid token error".to_string()),
        },
    }
}
