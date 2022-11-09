use apollo_router::graphql;
use apollo_router::layers::ServiceBuilderExt;
use apollo_router::plugin::Plugin;
use apollo_router::plugin::PluginInit;
use apollo_router::register_plugin;
use apollo_router::services::subgraph;
use apollo_router::services::supergraph;
use apollo_router::Context;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{decode, decode_header, jwk, DecodingKey, Header, Validation};
use reqwest::header::HeaderName;
use reqwest::header::HeaderValue;
use reqwest::StatusCode;
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;
use tokio::sync::oneshot::Sender;
use tower::{util::BoxService, BoxError, ServiceBuilder, ServiceExt};

// We are storing the configuration, but not using it. Hence the allow dead code.
#[allow(dead_code)]
pub struct JwksPlugin {
    configuration: Conf,
    // Which header to use; defaults to "Authorization"
    token_header: String,
    // Which token prefix to use; defaults to "Bearer"
    token_prefix: String,
    // Struct used to manage the JWKS for validation
    jwks_manager: JwksManager,
}

// JwksManager struct
//     jwks: stores the jwks keyset within an Arc (for cross channel communication) and RwLock (to avoid race conditions) as a string, which is parsed
//     by serde_json as needed
//     url: URL to fetch the JWKS from (expecting the .well-known/jwks.json path)
struct JwksManager {
    jwks: Arc<RwLock<String>>,
    url: String,
    // `Option` because in theory one can call `JwksManager::new()` but
    // not manager.poll() later, so `jwks` updater task may not be running at all.
    shutdown_hook: Option<Sender<bool>>,
}

/// JwksManager handles the JWKS for use with key validation and polling of an external JWKS JSON endpoint
impl JwksManager {
    /// Returns a new implementation of the JwksManager with a valid JWKS
    async fn new(url: &str) -> Result<Self, BoxError> {
        let jwks_string = JwksManager::fetch_jwks(url).await?;
        Ok(Self {
            jwks: Arc::new(RwLock::new(jwks_string)),
            url: url.to_string(),
            shutdown_hook: None,
        })
    }

    fn poll(&mut self) {
        // poll every 5 minutes for an updated JWKS; adjust as needed
        let mut poll_interval = tokio::time::interval(Duration::from_secs(60 * 5));
        let url = self.url.clone();
        let jwks_string = Arc::clone(&self.jwks);

        // This channel will only be used once to signal the shutdown.
        let (tx, mut rx) = oneshot::channel();
        self.shutdown_hook = Some(tx);
        // Spawn a new task used to poll for the JWKS, ensuring we don't block execution of requests
        tokio::spawn(async move {
            // Clone the string to safely pass into the loop
            let safe_jwks = Arc::clone(&jwks_string);

            // start the loop
            loop {
                let should_exit = match rx.try_recv() {
                    // got a shutdown message from the `drop`
                    Ok(_) => true,
                    // haven't got a message, but sender doesn't exist anymore
                    Err(TryRecvError::Closed) => true,
                    // no shutdown message yet
                    Err(TryRecvError::Empty) => false,
                };
                if should_exit {
                    break;
                }

                // move into a subroutine...
                {
                    tracing::debug!("Fetching JWKS from {}", &url);

                    // ... fetch the JWKS using the fetch_jwks function...
                    match JwksManager::fetch_jwks(&url).await {
                        Ok(jwks_response) => {
                            tracing::debug!("{}", jwks_response);

                            // ... lock RwLock for the write to the Arc'ed safe_jwks string ...
                            let mut s = safe_jwks.write().unwrap();
                            *s = jwks_response;
                            // if line above doesn't work try this:
                            // s.clear();
                            // s.push_str(&jwks_response);
                        }
                        Err(e) => {
                            // capture any errors and log out the error to avoid crashing the plugin
                            tracing::error!("Error received when fetching JWKS: {}", e)
                        }
                    }
                }
                // ... and finally await the next tokio tick- set by the interval above.
                poll_interval.tick().await;
            }
        });
    }

    // Returns the keyset (aka the JWKS in a format used by the library)
    fn retrieve_keyset(&self) -> Result<JwkSet, BoxError> {
        let keyset = self.jwks.read().unwrap();
        let jwks: jwk::JwkSet = serde_json::from_str(&keyset)?;
        Ok(jwks)
    }

    // simple function that returns back the JWKS as a string
    async fn fetch_jwks(url: &str) -> Result<String, BoxError> {
        let resp = reqwest::get(url).await?.text().await?;

        Ok(resp)
    }
}

impl Drop for JwksManager {
    fn drop(&mut self) {
        // `oneshot::Sender::send` consumes `self` so we use `take` to get
        // an owned `hook` instead of a reference to it.
        if let Some(hook) = self.shutdown_hook.take() {
            // we send a message to let manager's task know that it should
            // shutdown.
            let _ = hook.send(true);
        }
    }
}

// Configuration options for the actual plugin
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct Conf {
    jwks_url: String,
    token_header: Option<String>,
    token_prefix: Option<String>,
}

#[async_trait::async_trait]
impl Plugin for JwksPlugin {
    type Config = Conf;

    async fn new(init: PluginInit<Self::Config>) -> Result<Self, BoxError> {
        let configuration = init.config;

        // Setting sane defaults for the plugin
        let token_header = match configuration.token_header {
            Some(ref x) => x.trim().to_string(),
            None => "Authorization".to_string(),
        };

        let token_prefix = match configuration.token_prefix {
            Some(ref x) => x.trim().to_string(),
            None => "Bearer".to_string(),
        };

        // Instantiate the JwksManager (which fetches the initial JWKS value)
        let mut jm = JwksManager::new(&configuration.jwks_url).await.unwrap();
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
            .retrieve_keyset()
            .expect("Error retrieving JWKS from the JWKSManager");

        ServiceBuilder::new()
            .checkpoint(move |req: supergraph::Request| {
                // We are going to do a lot of similar checking so let's define a local function
                // to help reduce repetition
                fn failure_message(
                    context: Context,
                    msg: String,
                    status: StatusCode,
                ) -> Result<ControlFlow<supergraph::Response, supergraph::Request>, BoxError>
                {
                    let res = supergraph::Response::error_builder()
                        .error(graphql::Error::builder().message(msg).build())
                        .status_code(status)
                        .context(context)
                        .build()?;
                    Ok(ControlFlow::Break(res))
                }

                // The http_request is stored in a `RouterRequest` context.
                // We are going to check the headers for the presence of the header we're looking for as set by the configuration or default value
                let jwt_value_result = match req.supergraph_request.headers().get(&token_header) {
                    Some(value) => value.to_str(),
                    None =>
                    // Prepare an HTTP 401 response with a GraphQL error message
                    {
                        return failure_message(
                            req.context,
                            format!("Missing '{}' header", token_header),
                            StatusCode::UNAUTHORIZED,
                        )
                    }
                };

                // If we find the header, but can't convert it to a string, let the client know
                let jwt_value_untrimmed = match jwt_value_result {
                    Ok(value) => value,
                    Err(_not_a_string_error) => {
                        // Prepare an HTTP 400 response with a GraphQL error message
                        return failure_message(
                            req.context,
                            "Authorization' header is not convertible to a string".to_string(),
                            StatusCode::BAD_REQUEST,
                        );
                    }
                };

                // Let's trim out leading and trailing whitespace to be accommodating
                let jwt_value = jwt_value_untrimmed.trim();

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
                    // Prepare an HTTP 400 response with a GraphQL error message
                    return failure_message(
                        req.context,
                        "Header is not correctly formatted".to_string(),
                        StatusCode::UNAUTHORIZED,
                    );
                }

                // We know we have a "space" if the charcount is > 0, since we checked above. Split our string other
                // in (at most 2) sections.
                let jwt_parts: Vec<&str> = jwt_value.splitn(2, ' ').collect();

                if jwt_parts.len() != 2 && token_prefix.chars().count() > 0 {
                    // Prepare an HTTP 400 response with a GraphQL error message
                    return failure_message(
                        req.context,
                        "Header is not correctly formatted".to_string(),
                        StatusCode::UNAUTHORIZED,
                    );
                }

                // Trim off any trailing white space (not valid in BASE64 encoding)
                let jwt = jwt_parts[if token_prefix.chars().count() > 0 {
                    1
                } else {
                    0
                }]
                .trim_end();

                // decode the header (first part of the JWT)
                let header = decode_header(jwt);

                let jwt_head: Header;

                // Validate the JWT header; if not valid, return an error to the client
                match header {
                    Ok(v) => jwt_head = v,
                    Err(_v) => {
                        return failure_message(
                            req.context,
                            "JWT header section is not correctly formatted".to_string(),
                            StatusCode::BAD_REQUEST,
                        )
                    }
                }

                // Find the key ID (kid) value from the header; this may not exist for symmetrically signed JWTs, but
                // that is out of scope for this plugin; if you need symmetrically signed plugins, see: https://github.com/apollographql/router/tree/main/examples/jwt-auth
                let kid = match jwt_head.kid {
                    Some(k) => k,
                    None => {
                        return failure_message(
                            req.context,
                            "Missing valid kid value".to_string(),
                            StatusCode::BAD_REQUEST,
                        )
                    }
                };

                // From the keyset, find the matching kid value and then attempt to decode
                if let Some(jwk) = jwks.find(&kid) {
                    match jwk.algorithm {
                        AlgorithmParameters::RSA(ref rsa) => {
                            // set up the decoding key for the JWT from the JWK
                            let decoding_key =
                                DecodingKey::from_rsa_components(&rsa.n, &rsa.e).unwrap();
                            let validation = Validation::new(jwk.common.algorithm.unwrap());

                            // attempt to decode
                            let token_result = decode::<HashMap<String, serde_json::Value>>(
                                jwt,
                                &decoding_key,
                                &validation,
                            );

                            // check the result; if an error, throw an error to the requestor, otherwise set the decoded_token to the value
                            if let Err(_e) = token_result {
                                return failure_message(
                                    req.context,
                                    "Invalid JWT".to_string(),
                                    StatusCode::UNAUTHORIZED,
                                );
                            }

                            // push the JWT Header into the context to pass down to subgraphs
                            if let Err(e) = req.context.insert("JWTHeader", jwt_value.to_owned()) {
                                return failure_message(
                                    req.context,
                                    format!("couldn't store JWT header in context: {}", e),
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                );
                            };
                            Ok(ControlFlow::Continue(req))
                        }
                        _ => failure_message(
                            req.context,
                            "Unable to load RSA keys".to_string(),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ),
                    }
                } else {
                    failure_message(
                        req.context,
                        "Invalid JWT".to_string(),
                        StatusCode::UNAUTHORIZED,
                    )
                }
            })
            .service(service)
            .boxed()
    }

    // used to forward the header from the context set above
    fn subgraph_service(
        &self,
        _name: &str,
        service: BoxService<subgraph::Request, subgraph::Response, BoxError>,
    ) -> BoxService<subgraph::Request, subgraph::Response, BoxError> {
        let token_header = self.token_header.clone();

        ServiceBuilder::new()
            .map_request(move |mut req: subgraph::Request| {
                if let Ok(Some(data)) = req.context.get::<_, String>("JWTHeader") {
                    let th = token_header.to_string();
                    req.subgraph_request.headers_mut().insert(
                        HeaderName::from_bytes(th.as_bytes()).unwrap(),
                        HeaderValue::from_str(&data).unwrap(),
                    );
                }
                req
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
