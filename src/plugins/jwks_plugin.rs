use std::collections::HashMap;
use std::ops::ControlFlow;
use std::time::Duration;
use apollo_router_core::plugin::Plugin;
use apollo_router_core::{
    register_plugin, RouterRequest, RouterResponse, SubgraphRequest, SubgraphResponse, Context, ServiceBuilderExt
};
use jsonwebtoken::jwk::{JwkSet, AlgorithmParameters};
use jsonwebtoken::{decode, decode_header, jwk, DecodingKey, Validation, Header, TokenData};
use reqwest::StatusCode;
use schemars::JsonSchema;
use serde::Deserialize;
use std::sync::{Arc, RwLock};
use tower::{util::BoxService, BoxError, ServiceBuilder, ServiceExt};

struct JwksPlugin{
    token_header: String,
    token_prefix: String,
    jwks_manager: JwksManager,
}

struct JwksManager{
    jwks: Arc<RwLock<String>>,
    url: String,
}

impl JwksManager {
    async fn new(url: &str) -> Result<Self, BoxError>{       
        let jwks_string = JwksManager::fetch_jwks(url).await.unwrap(); 
        return Ok(Self{
            jwks: Arc::new(RwLock::new(jwks_string)),
            url: url.to_string()
        })
    }

    fn poll(&self) {
        let mut poll_interval = tokio::time::interval(Duration::from_secs(10));
        let url = self.url.clone();
        let jwks_string = Arc::clone(&self.jwks);

        tokio::spawn( async move {
            let safe_jwks = Arc::clone(&jwks_string);

            loop {
                {
                    tracing::info!("Fetching JWKS");
                    let jwks_response = JwksManager::fetch_jwks(&url).await.unwrap();
                    tracing::debug!("{}", jwks_response);
                    
                    let mut s = safe_jwks.write().unwrap();
                    *s = jwks_response;
                }
                poll_interval.tick().await; 
            }
        });
    }

    fn retrieve_keyset(&self) -> Result<JwkSet, BoxError>{
        let keyset = self.jwks.read().unwrap();
        let jwks: jwk::JwkSet = serde_json::from_str(&keyset).unwrap();
        Ok(jwks)
    }

    async fn fetch_jwks(url: &str) -> Result<String, BoxError>{
        let resp = reqwest::get(url)
            .await?
            .text()
            .await?;
        
        Ok(resp)
    }
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct Conf {
    jwks_url: String,
    token_header: Option<String>,
    token_prefix: Option<String>,
}

// This is a bare-bones plugin that you can duplicate when creating your own.
#[async_trait::async_trait]
impl Plugin for JwksPlugin {
    type Config = Conf;

    async fn new(configuration: Self::Config) -> Result<Self, BoxError> {
        let token_header = match configuration.token_header {
            None => "Authorization".to_string(),
            Some(x)=>x.trim().to_string(),
        };
        
        let token_prefix = match configuration.token_prefix{
            None=>"Bearer ".to_string(), // make case insensitive
            Some(x)=> x.trim().to_string() + " ",
        };
        
        let jm = JwksManager::new(&configuration.jwks_url).await.unwrap();
        jm.poll();

        tracing::info!("Successfully fetched JWT Key set. JWKS Plugin started");
        Ok(Self {
            jwks_manager: jm,
            token_header,
            token_prefix,
        })
    }

    fn router_service(
        &mut self,
        service: BoxService<RouterRequest, RouterResponse, BoxError>,
    ) -> BoxService<RouterRequest, RouterResponse, BoxError> {
        let token_header = self.token_header.clone();
        let token_prefix = self.token_prefix.clone();
        let jwks = self.jwks_manager.retrieve_keyset().unwrap();

        ServiceBuilder::new()
            .checkpoint(move |req: RouterRequest| {
                // We are going to do a lot of similar checking so let's define a local function
                // to help reduce repetition
                fn failure_message(
                    context: Context,
                    msg: String,
                    status: StatusCode,
                ) -> Result<ControlFlow<RouterResponse, RouterRequest>, BoxError> {
                    let res = RouterResponse::error_builder()
                        .errors(vec![apollo_router_core::Error {
                            message: msg,
                            ..Default::default()
                        }])
                        .status_code(status)
                        .context(context)
                        .build()?;
                    Ok(ControlFlow::Break(res))
                }

                // The http_request is stored in a `RouterRequest` context.
                // We are going to check the headers for the presence of the header we're looking for
                // We are implementing: https://www.rfc-editor.org/rfc/rfc6750
                // so check for our AUTHORIZATION header.
                let jwt_value_result = match req.originating_request.headers().get(&token_header) {
                    Some(value) => value.to_str(),
                    None =>
                        // Prepare an HTTP 401 response with a GraphQL error message
                        return failure_message(req.context, format!("Missing '{}' header", token_header), StatusCode::UNAUTHORIZED),
                };

                // If we find the header, but can't convert it to a string, let the client know
                let jwt_value_untrimmed = match jwt_value_result {
                    Ok(value) => value,
                    Err(_not_a_string_error) => {
                        // Prepare an HTTP 400 response with a GraphQL error message
                        return failure_message(req.context,
                                               "AUTHORIZATION' header is not convertible to a string".to_string(),
                            StatusCode::BAD_REQUEST,
                        );
                    }
                };

                // Let's trim out leading and trailing whitespace to be accommodating
                let jwt_value = jwt_value_untrimmed.trim();

                // Make sure the format of our message matches our expectations
                // Technically, the spec is case sensitive, but let's accept
                // case variations
                if !jwt_value.to_uppercase().as_str().starts_with(&token_prefix.to_uppercase()) {
                    // Prepare an HTTP 400 response with a GraphQL error message
                    return failure_message(req.context,
                                           format!("'{jwt_value_untrimmed}' is not correctly formatted"),
                        StatusCode::BAD_REQUEST,
                    );
                }

                // We know we have a "space", since we checked above. Split our string
                // in (at most 2) sections.
                let jwt_parts: Vec<&str> = jwt_value.splitn(2, ' ').collect();
                if jwt_parts.len() != 2 {
                    // Prepare an HTTP 400 response with a GraphQL error message
                    return failure_message(req.context,
                                           format!("'{jwt_value}' is not correctly formatted"),
                        StatusCode::BAD_REQUEST,
                    );
                }

                // Trim off any trailing white space (not valid in BASE64 encoding)
                let jwt = jwt_parts[1].trim_end();

                let header = decode_header(jwt);

                let jwt_head: Header;

                match header {
                    Ok(v)=>{jwt_head=v},
                    Err(_v)=>{
                        return failure_message(req.context, "".to_string(), StatusCode::BAD_REQUEST)
                    }
                }

                let kid = match jwt_head.kid {
                    Some(k)=>k,
                    None => return failure_message(req.context, "Missing valid kid value".to_string(), StatusCode::BAD_REQUEST)
                };
                if let Some(j) = jwks.find(&kid) {
                    match j.algorithm {
                        AlgorithmParameters::RSA(ref rsa) => {
                            let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e).unwrap();
                            let mut validation = Validation::new(j.common.algorithm.unwrap());
                            validation.validate_exp = false;
                            let token_result = decode::<HashMap<String, serde_json::Value>>(jwt, &decoding_key, &validation);
                            let decoded_token: TokenData<HashMap<String, serde_json::Value>>;

                            match token_result {
                                Ok(v)=>{decoded_token = v},
                                Err(_v)=>{
                                    return failure_message(req.context, format!("'{jwt_value}' is not correctly formatted"), StatusCode::BAD_REQUEST);
                                }
                            }
                            match req.context.insert("JWTClaims", decoded_token.claims) {
                                Ok(_v) => Ok(ControlFlow::Continue(req)),
                                Err(err) => {
                                    return failure_message(req.context,
                                                            format!("couldn't store JWT claims in context: {}", err),
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                    );
                                }
                            }
                        }
                        _ => unreachable!("this should be a RSA"),
                    }
                } else {
                    return Err("No matching JWK found for the given kid".into());
                }
            })
            .service(service)
            .boxed()
    }

    fn subgraph_service(
        &mut self,
        _name: &str,
        service: BoxService<SubgraphRequest, SubgraphResponse, BoxError>,
    ) -> BoxService<SubgraphRequest, SubgraphResponse, BoxError> {
        service
    }
}

register_plugin!("example", "jwks", JwksPlugin);

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn plugin_registered() {
        apollo_router_core::plugins()
            .get("example.jwks")
            .expect("Plugin not found")
            .create_instance(&serde_json::json!({"jwks_url" : "https://dev-zzp5enui.us.auth0.com/.well-known/jwks.json"}))
            .await
            .unwrap();
    }
}