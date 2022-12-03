use anyhow::anyhow;
use reqwest::StatusCode;
use tower::BoxError;
use crate::fixtures::json_web_key_set::{create_jwk_set, create_rsa_key};
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

use jwks_router_plugin::jwks_manager;

mod fixtures;


// #[test!]
#[tokio::test]
async fn it_retrieves_to_jwks() -> Result<(), BoxError> {
    let kid = "foo";
    let rsa = create_rsa_key();
    let mock_server = MockServer::start().await;
    let key_set = create_jwk_set(&rsa, kid.to_string());

    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(StatusCode::OK)
            .set_body_json(key_set)
        )
        .mount(&mock_server)
        .await;

    let url = format!("{}/jwks.json", &mock_server.uri());
    let mgr = jwks_manager::JwksManager::new(url.as_str()).await?;
    let key_set = &mgr.retrieve_key_set()?;

    let jwk = key_set.find(kid).ok_or_else(|| anyhow!("Expected to find the kid"))?;

    // if let Some (token) = jwk {
    //     assert_eq!(&kid.to_string(), token.common.key_id.as_ref().ok_or_else(|| anyhow!("Expected shit"))?)
    // }
    assert_eq!(&kid.to_string(), jwk.common.key_id.as_ref().ok_or_else(|| anyhow!("Expected shit"))?);

    Ok(())
}
