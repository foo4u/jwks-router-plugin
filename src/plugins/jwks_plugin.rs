use super::error::JwtValidationError;
use crate::jwks_manager::JwksManager;
use crate::plugins::jwk_adapter::JwkAdapter;
use apollo_router::graphql;
use apollo_router::layers::ServiceBuilderExt;
use apollo_router::plugin::Plugin;
use apollo_router::plugin::PluginInit;
use apollo_router::register_plugin;
use apollo_router::services::supergraph;
use apollo_router::Context;
use reqwest::StatusCode;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json_bytes::{json, Map as JsonMap};
use std::ops::ControlFlow;
use tower::{util::BoxService, BoxError, ServiceBuilder, ServiceExt};

const DEFAULT_AUTHORIZATION_HEADER: &str = "Authorization";
const DEFAULT_TOKEN_PREFIX: &str = "Bearer";

// Configuration options for the actual plugin
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct Conf {
    jwks_url: String,
    token_header: Option<String>,
    token_prefix: Option<String>,
}

pub struct JwksPlugin {
    #[allow(dead_code)]
    configuration: Conf,
    // Which header to use; defaults to "Authorization"
    token_header: String,
    // Which token prefix to use; defaults to "Bearer"
    token_prefix: String,
    // Struct used to manage the JWKS for validation
    jwks_manager: JwksManager,
}

impl JwksPlugin {
    fn authentication_error(
        context: Context,
        msg: String,
        status: StatusCode,
    ) -> Result<ControlFlow<supergraph::Response, supergraph::Request>, BoxError> {
        let mut ext = JsonMap::with_capacity(1);
        ext.insert("error", json!(msg));
        let res = supergraph::Response::error_builder()
            .error(
                graphql::Error::builder()
                    .message("FORBIDDEN")
                    .extensions(ext)
                    .build(),
            )
            .status_code(status)
            .context(context)
            .build()?;
        Ok(ControlFlow::Break(res))
    }
}

#[async_trait::async_trait]
impl Plugin for JwksPlugin {
    type Config = Conf;

    async fn new(init: PluginInit<Self::Config>) -> Result<Self, BoxError> {
        let configuration = init.config;

        // Set sane defaults for the plugin
        let token_header = match configuration.token_header {
            Some(ref x) => x.trim().to_string(),
            None => DEFAULT_AUTHORIZATION_HEADER.to_string(),
        };

        let token_prefix = match configuration.token_prefix {
            Some(ref x) => x.trim().to_string(),
            None => DEFAULT_TOKEN_PREFIX.to_string(),
        };

        // Instantiate the JwksManager (which fetches the initial JWKS value)
        let mut jm = JwksManager::new(&configuration.jwks_url, None).await.unwrap();
        // start the polling; comment out if you don't want to poll for changes
        jm.poll();

        // Success! Log we are ready to go.
        tracing::info!("Successfully fetched JWT Key set. JWKS Plugin started");

        Ok(Self {
            configuration,
            jwks_manager: jm,
            token_header,
            token_prefix,
        })
    }

    fn supergraph_service(
        self: &JwksPlugin,
        service: BoxService<supergraph::Request, supergraph::Response, BoxError>,
    ) -> BoxService<supergraph::Request, supergraph::Response, BoxError> {
        let token_header = self.token_header.clone();
        let token_prefix = self.token_prefix.clone();
        let jwks = self
            .jwks_manager
            .retrieve_key_set()
            .expect("Error retrieving JWKS from the JWKSManager"); // FIXME: this will crash the router

        ServiceBuilder::new()
            .checkpoint(move |req: supergraph::Request| {
                // The http_request is stored in a `RouterRequest` context.
                let jwt_value_result = match req.supergraph_request.headers().get(&token_header) {
                    Some(value) => value.to_str(),
                    None =>
                    // Prepare an HTTP 401 response with a GraphQL error message
                    {
                        return JwksPlugin::authentication_error(
                            req.context,
                            format!("Missing '{}' header", token_header),
                            StatusCode::UNAUTHORIZED,
                        )
                    }
                };

                // If we find the header, but can't convert it to a string, let the client know
                let jwt_value = match jwt_value_result {
                    Ok(value) => value.trim(),
                    Err(_not_a_string_error) => {
                        // Prepare an HTTP 400 response with a GraphQL error message
                        return JwksPlugin::authentication_error(
                            req.context,
                            "Authorization header is not convertible to a string".to_string(),
                            StatusCode::BAD_REQUEST,
                        );
                    }
                };

                // Trim off any trailing white space (not valid in BASE64 encoding)
                let jwt = match JwkAdapter::parse_jwt_value(&token_prefix, jwt_value) {
                    Ok(token) => token,
                    Err(error) => {
                        return JwksPlugin::authentication_error(
                            req.context,
                            format!("{}", error),
                            StatusCode::UNAUTHORIZED,
                        )
                    }
                };

                if let Err(e) = JwkAdapter::validate(jwt.as_str(), &jwks) {
                    let status_code = match e {
                        JwtValidationError::MissingKid => StatusCode::BAD_REQUEST,
                        JwtValidationError::UnknownKid(_) => StatusCode::BAD_REQUEST,
                        JwtValidationError::UnsupportedAlgorithm(_) => StatusCode::BAD_REQUEST,
                        _ => StatusCode::UNAUTHORIZED,
                    };
                    return JwksPlugin::authentication_error(
                        req.context,
                        format!("{}", e),
                        status_code,
                    );
                }

                Ok(ControlFlow::Continue(req))
            })
            .service(service)
            .boxed()
    }
}

register_plugin!("example", "jwks", JwksPlugin);

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn plugin_registered() {
        let config = serde_json::json!({
            "plugins": {
                "example.jwks": {
                    "jwks_url": "https://dev-zzp5enui.us.auth0.com/.well-known/jwks.json" ,
                }
            }
        });
        apollo_router::TestHarness::builder()
            .configuration_json(config)
            .unwrap()
            .build()
            .await
            .unwrap();
    }
}
