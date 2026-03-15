use anyhow::{anyhow, Context};
use reqwest::Client as HttpClient;
use tracing::{debug, info};

use crate::crypto::{self, SymmetricKey};
use crate::models::{Cipher, CipherType, PreloginResponse, SyncResponse, TokenResponse};

/// Bitwarden API client
pub struct BitwardenClient {
    http: HttpClient,
    api_url: String,
    identity_url: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
    token_expiry: Option<std::time::Instant>,
    device_id: String,
    user_key: Option<SymmetricKey>,
}

/// A decrypted SSH key ready for use by the agent.
#[derive(Debug, Clone)]
pub struct DecryptedSshKey {
    pub private_key_pem: String,
    pub name: String,
    pub cipher_id: String,
}

impl BitwardenClient {
    pub fn new(base_url: &str, api_url: &str, identity_url: &str) -> Self {
        let _ = base_url; // Used by callers for URL construction
        Self {
            http: HttpClient::new(),
            api_url: api_url.to_string(),
            identity_url: identity_url.to_string(),
            access_token: None,
            refresh_token: None,
            token_expiry: None,
            device_id: uuid::Uuid::new_v4().to_string(),
            user_key: None,
        }
    }

    /// Create a client with a specific device_id (restored from session file).
    pub fn new_with_device_id(
        base_url: &str,
        api_url: &str,
        identity_url: &str,
        device_id: &str,
    ) -> Self {
        let _ = base_url;
        Self {
            http: HttpClient::new(),
            api_url: api_url.to_string(),
            identity_url: identity_url.to_string(),
            access_token: None,
            refresh_token: None,
            token_expiry: None,
            device_id: device_id.to_string(),
            user_key: None,
        }
    }

    /// Step 1: Prelogin — get KDF parameters for the user's account.
    pub async fn prelogin(&self, email: &str) -> anyhow::Result<PreloginResponse> {
        let url = format!("{}/accounts/prelogin", self.identity_url);
        debug!("Prelogin: POST {}", url);

        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "email": email }))
            .send()
            .await
            .context("Prelogin request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Prelogin failed ({}): {}", status, body));
        }

        let body = resp
            .text()
            .await
            .context("Failed to read prelogin response body")?;
        debug!("Prelogin response: {}", body);

        serde_json::from_str::<PreloginResponse>(&body).context("Failed to parse prelogin response")
    }

    /// Step 2: Login with email + master password.
    ///
    /// Derives master key, computes password hash, authenticates with the server,
    /// and decrypts the user's symmetric key.
    pub async fn login_password(&mut self, email: &str, password: &str) -> anyhow::Result<()> {
        // 2a: Get KDF params
        let prelogin = self.prelogin(email).await?;
        info!(
            "KDF: {:?}, iterations: {}",
            prelogin.kdf, prelogin.kdf_iterations
        );

        // 2b: Derive master key
        let master_key = crypto::derive_master_key(password, email, &prelogin)
            .context("Failed to derive master key")?;

        // 2c: Derive password hash for server
        let password_hash = crypto::derive_password_hash(&master_key, password)
            .context("Failed to derive password hash")?;

        // 2d: Request token
        let url = format!("{}/connect/token", self.identity_url);
        debug!("Login: POST {}", url);

        let params = [
            ("grant_type", "password"),
            ("username", email),
            ("password", &password_hash),
            ("scope", "api offline_access"),
            ("client_id", "cli"),
            ("deviceType", "14"),
            ("deviceIdentifier", &self.device_id),
            ("deviceName", "sshwarden"),
        ];

        let resp = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await
            .context("Login request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Login failed ({}): {}", status, body));
        }

        let body = resp
            .text()
            .await
            .context("Failed to read token response body")?;
        debug!(
            "Token response Key prefix: {}",
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v
                    .get("Key")
                    .or(v.get("key"))
                    .and_then(|k| k.as_str().map(|s| s.chars().take(20).collect::<String>())))
                .unwrap_or_else(|| "N/A".to_string())
        );

        let token_resp: TokenResponse =
            serde_json::from_str(&body).context("Failed to parse token response")?;

        self.access_token = Some(token_resp.access_token);
        self.refresh_token = token_resp.refresh_token.clone();
        self.token_expiry = Some(
            std::time::Instant::now()
                + std::time::Duration::from_secs(token_resp.expires_in),
        );

        // 2e: Decrypt user symmetric key
        if let Some(ref encrypted_key) = token_resp.key {
            let user_key = crypto::decrypt_user_key(encrypted_key, &master_key)
                .context("Failed to decrypt user key from token response")?;
            self.user_key = Some(user_key);
            info!("Login successful, user key decrypted");
        } else {
            return Err(anyhow!("Token response missing encrypted user key"));
        }

        Ok(())
    }

    /// Step 3: Sync vault and return all SSH key ciphers (decrypted).
    pub async fn sync_ssh_keys(&self) -> anyhow::Result<Vec<DecryptedSshKey>> {
        let access_token = self
            .access_token
            .as_ref()
            .ok_or_else(|| anyhow!("Not authenticated"))?;
        let user_key = self
            .user_key
            .as_ref()
            .ok_or_else(|| anyhow!("User key not available"))?;

        let url = format!("{}/sync?excludeDomains=true", self.api_url);
        debug!("Sync: GET {}", url);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .context("Sync request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Sync failed ({}): {}", status, body));
        }

        let sync: SyncResponse = resp.json().await.context("Failed to parse sync response")?;

        info!("Sync complete: {} ciphers total", sync.ciphers.len());

        // Filter SSH key ciphers and decrypt
        let ssh_ciphers: Vec<&Cipher> = sync
            .ciphers
            .iter()
            .filter(|c| c.cipher_type == CipherType::SshKey && c.deleted_date.is_none())
            .collect();

        info!("Found {} SSH key ciphers", ssh_ciphers.len());

        let mut keys = Vec::new();
        for cipher in ssh_ciphers {
            match self.decrypt_ssh_cipher(cipher, user_key) {
                Ok(key) => keys.push(key),
                Err(e) => {
                    tracing::warn!(
                        cipher_id = %cipher.id,
                        error = %e,
                        "Failed to decrypt SSH cipher, skipping"
                    );
                }
            }
        }

        info!("Successfully decrypted {} SSH keys", keys.len());
        Ok(keys)
    }

    fn decrypt_ssh_cipher(
        &self,
        cipher: &Cipher,
        user_key: &SymmetricKey,
    ) -> anyhow::Result<DecryptedSshKey> {
        // If cipher has its own key (organization cipher), decrypt it first
        let effective_key = if let Some(ref cipher_key_enc) = cipher.key {
            let cipher_key_bytes = crypto::decrypt_enc_string(cipher_key_enc, user_key)
                .context("Failed to decrypt cipher key")?;
            if cipher_key_bytes.len() != 64 {
                return Err(anyhow!(
                    "Cipher key has unexpected length: {}",
                    cipher_key_bytes.len()
                ));
            }
            SymmetricKey {
                enc_key: cipher_key_bytes[..32].to_vec(),
                mac_key: cipher_key_bytes[32..].to_vec(),
            }
        } else {
            user_key.clone()
        };

        let ssh_data = cipher.ssh_key.as_ref().ok_or_else(|| {
            anyhow!(
                "Cipher {} is SshKey type but has no ssh_key data",
                cipher.id
            )
        })?;

        let private_key_pem =
            crypto::decrypt_enc_string_to_string(&ssh_data.private_key, &effective_key)
                .context("Failed to decrypt SSH private key")?;

        let name = match cipher.name {
            Some(ref enc_name) => crypto::decrypt_enc_string_to_string(enc_name, &effective_key)
                .unwrap_or_else(|_| "unnamed".to_string()),
            None => "unnamed".to_string(),
        };

        Ok(DecryptedSshKey {
            private_key_pem,
            name,
            cipher_id: cipher.id.clone(),
        })
    }

    pub fn is_authenticated(&self) -> bool {
        self.access_token.is_some()
    }

    pub fn has_user_key(&self) -> bool {
        self.user_key.is_some()
    }

    /// Get a reference to the user symmetric key (for unlock/lock flows).
    pub fn user_key(&self) -> Option<&SymmetricKey> {
        self.user_key.as_ref()
    }

    /// Set the user symmetric key (e.g., after unlock via PIN or biometric).
    pub fn set_user_key(&mut self, key: SymmetricKey) {
        self.user_key = Some(key);
    }

    /// Clear the user symmetric key (lock the vault).
    pub fn clear_user_key(&mut self) {
        self.user_key = None;
    }

    /// Get the current access token.
    pub fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }

    /// Get the current refresh token.
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// Get the device identifier.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Get the identity URL (for session file storage).
    pub fn identity_url(&self) -> &str {
        &self.identity_url
    }

    /// Set the refresh token (e.g., restored from session file).
    pub fn set_refresh_token(&mut self, token: String) {
        self.refresh_token = Some(token);
    }

    /// Check if the access token is expiring within 5 minutes.
    pub fn is_token_expiring_soon(&self) -> bool {
        match self.token_expiry {
            Some(expiry) => {
                let now = std::time::Instant::now();
                if now >= expiry {
                    return true;
                }
                expiry.duration_since(now) < std::time::Duration::from_secs(300)
            }
            None => self.access_token.is_some(), // No expiry tracked, assume expiring
        }
    }

    /// Refresh the access token using the stored refresh token.
    ///
    /// Sends `grant_type=refresh_token` to the identity endpoint and updates
    /// access_token, refresh_token, and token_expiry.
    pub async fn refresh_access_token(&mut self) -> anyhow::Result<()> {
        let refresh_token = self
            .refresh_token
            .as_ref()
            .ok_or_else(|| anyhow!("No refresh token available"))?
            .clone();

        let url = format!("{}/connect/token", self.identity_url);
        debug!("Token refresh: POST {}", url);

        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", "cli"),
        ];

        let resp = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await
            .context("Token refresh request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Token refresh failed ({}): {}", status, body));
        }

        let body = resp
            .text()
            .await
            .context("Failed to read token refresh response")?;

        let token_resp: TokenResponse =
            serde_json::from_str(&body).context("Failed to parse token refresh response")?;

        self.access_token = Some(token_resp.access_token);
        if let Some(new_refresh) = token_resp.refresh_token {
            self.refresh_token = Some(new_refresh);
        }
        self.token_expiry = Some(
            std::time::Instant::now()
                + std::time::Duration::from_secs(token_resp.expires_in),
        );

        info!("Access token refreshed successfully");
        Ok(())
    }
}
