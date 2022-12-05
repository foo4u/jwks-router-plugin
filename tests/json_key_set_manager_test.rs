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
use crate::fixtures::json_web_key_set::{create_jwk_set, create_rsa_key};
use anyhow::{anyhow, Error};
use reqwest::StatusCode;
use std::time::Duration;
use jsonwebtoken::jwk::JwkSet;
use tower::BoxError;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use jwks_router_plugin::jwks_manager;

mod fixtures;

async fn mock_jwks_response(mock_server: &MockServer, key_set: JwkSet, mock_times: u64) {
     Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(StatusCode::OK).set_body_json(key_set))
         .up_to_n_times(mock_times)
        .mount(&mock_server)
        .await;
}

fn mock_jwks_uri(mock_server: &MockServer) -> String {
    format!("{}/jwks.json", mock_server.uri())
}

#[tokio::test]
async fn it_retrieves_to_jwks() -> Result<(), BoxError> {
    let kid = "foo";
    let rsa = create_rsa_key();
    let mock_server = MockServer::start().await;
    let key_set = create_jwk_set(&rsa, kid.to_string());

    mock_jwks_response(&mock_server, key_set, 100).await;

    let mut mgr =
        jwks_manager::JwksManager::new(mock_jwks_uri(&mock_server).as_str(), Some(Duration::from_millis(10))).await?;
    let _ = &mgr.poll();

    let result_key_set = &mgr.retrieve_key_set()?;

    let jwk = result_key_set
        .find(kid)
        .ok_or_else(|| anyhow!("Expected to find a JWK with the kid {}", &kid))?;

    assert_eq!(
        &kid.to_string(),
        jwk.common
            .key_id
            .as_ref()
            .ok_or_else(|| anyhow!("Expected JWK to contain a kid claim"))?
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn it_handles_token_refresh_errors() -> Result<(), BoxError> {
    let kid = "foo";
    let rsa = create_rsa_key();
    let mock_server = MockServer::start().await;
    let key_set = create_jwk_set(&rsa, kid.to_string());

    mock_jwks_response(&mock_server, key_set, 1).await;

    let mut mgr =
        jwks_manager::JwksManager::new(mock_jwks_uri(&mock_server).as_str(), Some(Duration::from_millis(200))).await?;
    let _ = &mgr.poll();
    let _x = &mgr.retrieve_key_set()?;

    std::thread::sleep(Duration::from_secs(1));

    let result_key_set = &mgr.retrieve_key_set()?;

    let jwk = result_key_set
        .find(kid)
        .ok_or_else(|| anyhow!("Expected to find kid {}", &kid))?;

    assert_eq!(
        &kid.to_string(),
        jwk.common
            .key_id
            .as_ref()
            .ok_or_else(|| anyhow!("Expected claims to contain a kid"))?
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn it_returns_an_error_if_key_set_not_retrievable_on_new() -> Result<(), Error> {
    let mock_server = MockServer::start().await;

    let mgr =
        jwks_manager::JwksManager::new(mock_jwks_uri(&mock_server).as_str(), Some(Duration::from_millis(200))).await;

    match mgr {
        Ok(_) => { Err(anyhow!("Expected manager startup to fail")) },
        Err(_e) => {
            Ok(())
        }
    }
}
