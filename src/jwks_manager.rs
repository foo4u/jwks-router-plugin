#![warn(clippy::unwrap_used)]
use std::sync::{Arc, RwLock};
use std::time::Duration;

use jsonwebtoken::jwk::JwkSet;
use reqwest::StatusCode;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;
use tokio::sync::oneshot::Sender;
use tower::BoxError;

#[derive(Error, Debug)]
pub enum KeySetError {
    #[error("JWKS endpoint responded with HTTP {0}")]
    HttpError(StatusCode),
}

// JwksManager struct
//     jwks: stores the jwks keyset within an Arc (for cross channel communication) and RwLock (to avoid race conditions) as a string, which is parsed
//     by serde_json as needed
//     url: URL to fetch the JWKS from (expecting the .well-known/jwks.json path)
pub struct JwksManager {
    jwks: Arc<RwLock<String>>,
    url: String,
    poll_interval: Duration,
    reqwuest_client: reqwest::Client,
    // `Option` because in theory one can call `JwksManager::new()` but
    // not manager.poll() later, so `jwks` updater task may not be running at all.
    shutdown_hook: Option<Sender<bool>>,
}

/// JwksManager handles the JWKS for use with key validation and polling of an external JWKS JSON endpoint
impl JwksManager {
    /// Returns a new implementation of the JwksManager with a valid JWKS
    pub async fn new(url: &str, poll_interval: Option<Duration>) -> Result<Self, BoxError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .build()?;
        let jwks_string = JwksManager::fetch_key_set(client.clone(), url).await?;
        Ok(Self {
            jwks: Arc::new(RwLock::new(jwks_string)),
            url: url.to_string(),
            poll_interval: poll_interval.unwrap_or(Duration::from_secs(60 * 5)),
            reqwuest_client: client,
            shutdown_hook: None,
        })
    }

    pub fn poll(&mut self) {
        let mut poll_interval = tokio::time::interval(self.poll_interval);
        let url = self.url.clone();
        let jwks_string = Arc::clone(&self.jwks);
        let client = self.reqwuest_client.clone();

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

                println!("Got should exit of {}", should_exit);

                if should_exit {
                    break;
                }

                tracing::debug!("Fetching JWKS from {}", &url);

                match JwksManager::fetch_key_set(client.clone(), &url).await {
                    Ok(jwks_response) => {
                        tracing::debug!("{}", jwks_response);
                        // ... lock RwLock for the write to the Arc'ed safe_jwks string ...
                        let mut s = safe_jwks.write().unwrap();
                        *s = jwks_response;
                    }
                    Err(e) => {
                        // capture any errors and log out the error to avoid crashing the plugin
                        tracing::error!("Error received when fetching JWKS: {}", e);
                        println!("Error received when fetching JWKS: {}", e);
                    }
                }

                poll_interval.tick().await;
            }
        });
    }

    // Returns the key set (aka the JWKS in a format used by the library)
    pub fn retrieve_key_set(&self) -> Result<JwkSet, BoxError> {
        // FIXME: is this unsafe?
        let key_set = self.jwks.read().unwrap();
        let jwks: JwkSet = serde_json::from_str(&key_set)?;
        Ok(jwks)
    }

    /// Retrieves the key set from the given JWKS URL.
    async fn fetch_key_set(client: reqwest::Client, url: &str) -> Result<String, BoxError> {
        // let res = client.get(url).await?;
        let res = client.get(url).send().await?;

        if res.status() != StatusCode::OK {
            return Err(BoxError::from(KeySetError::HttpError(res.status())));
        }

        let text = res.text().await?;
        let key_set: JwkSet = serde_json::from_str(&text)?;
        tracing::debug!("Retrieved {} for {:?}", url, &key_set);

        Ok(text)
    }
}

impl Drop for JwksManager {
    fn drop(&mut self) {
        if let Some(hook) = self.shutdown_hook.take() {
            // shutdown
            let _ = hook.send(true);
        }
    }
}
