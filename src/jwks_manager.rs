use std::sync::{Arc, RwLock};
use std::time::Duration;

use jsonwebtoken::jwk::JwkSet;
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;
use tokio::sync::oneshot::Sender;
use tower::BoxError;

// JwksManager struct
//     jwks: stores the jwks keyset within an Arc (for cross channel communication) and RwLock (to avoid race conditions) as a string, which is parsed
//     by serde_json as needed
//     url: URL to fetch the JWKS from (expecting the .well-known/jwks.json path)
pub struct JwksManager {
    jwks: Arc<RwLock<String>>,
    url: String,
    // `Option` because in theory one can call `JwksManager::new()` but
    // not manager.poll() later, so `jwks` updater task may not be running at all.
    shutdown_hook: Option<Sender<bool>>,
}

/// JwksManager handles the JWKS for use with key validation and polling of an external JWKS JSON endpoint
impl JwksManager {
    /// Returns a new implementation of the JwksManager with a valid JWKS
    pub async fn new(url: &str) -> Result<Self, BoxError> {
        let jwks_string = JwksManager::fetch_key_set(url).await?;
        Ok(Self {
            jwks: Arc::new(RwLock::new(jwks_string)),
            url: url.to_string(),
            shutdown_hook: None,
        })
    }

    pub fn poll(&mut self) {
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
                    match JwksManager::fetch_key_set(&url).await {
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

    // Returns the key set (aka the JWKS in a format used by the library)
    pub fn retrieve_key_set(&self) -> Result<JwkSet, BoxError> {
        // FIXME: is this unsafe?
        let key_set = self.jwks.read().unwrap();
        let jwks: JwkSet = serde_json::from_str(&key_set)?;
        Ok(jwks)
    }

    // simple function that returns back the JWKS as a string
    async fn fetch_key_set(url: &str) -> Result<String, BoxError> {
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
