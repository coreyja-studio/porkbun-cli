//! Porkbun API client for domain and DNS management.
//!
//! This module provides a typed client for the [Porkbun API](https://porkbun.com/api/json/v3/documentation).
//!
//! # Authentication
//!
//! All API requests require authentication via API key and secret key.
//! Credentials are loaded from the mnemon secrets manager:
//!
//! ```bash
//! mnemon secrets get porkbun-api api-key
//! mnemon secrets get porkbun-api secret-key
//! ```
//!
//! # Example
//!
//! ```no_run
//! use porkbun_cli::client::{Credentials, PorkbunClient};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let credentials = Credentials::from_mnemon()?;
//!     let client = PorkbunClient::new(credentials);
//!
//!     // Check domain availability
//!     let result = client.check_domain("example.com").await?;
//!     println!("Available: {:?}", result.avail);
//!
//!     // List DNS records
//!     let records = client.list_records("mydomain.com").await?;
//!     for record in records {
//!         println!("{}: {} -> {}", record.record_type, record.name, record.content);
//!     }
//!
//!     Ok(())
//! }
//! ```

use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Base URL for the Porkbun API v3.
const API_BASE: &str = "https://api.porkbun.com/api/json/v3";

/// Errors that can occur when interacting with the Porkbun API.
#[derive(Error, Debug)]
pub enum PorkbunError {
    /// HTTP request failed (network error, timeout, etc.)
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// API returned an error response
    #[error("API error: {0}")]
    Api(String),
    /// Failed to load credentials from mnemon
    #[error("Failed to get credentials: {0}")]
    Credentials(String),
}

/// API credentials for Porkbun authentication.
///
/// Both keys are required for all API requests.
#[derive(Debug, Clone)]
pub struct Credentials {
    /// The API key from your Porkbun account settings
    pub api_key: String,
    /// The secret API key from your Porkbun account settings
    pub secret_key: String,
}

impl Credentials {
    /// Load credentials from the mnemon secrets manager.
    ///
    /// Expects a secret named `porkbun-api` with fields `api-key` and `secret-key`.
    ///
    /// # Errors
    ///
    /// Returns an error if mnemon is not available or the secret doesn't exist.
    pub fn from_mnemon() -> Result<Self, PorkbunError> {
        let api_key = std::process::Command::new("mnemon")
            .args(["secrets", "get", "porkbun-api", "api-key"])
            .output()
            .map_err(|e| PorkbunError::Credentials(e.to_string()))?;

        if !api_key.status.success() {
            return Err(PorkbunError::Credentials(
                String::from_utf8_lossy(&api_key.stderr).to_string(),
            ));
        }

        let secret_key = std::process::Command::new("mnemon")
            .args(["secrets", "get", "porkbun-api", "secret-key"])
            .output()
            .map_err(|e| PorkbunError::Credentials(e.to_string()))?;

        if !secret_key.status.success() {
            return Err(PorkbunError::Credentials(
                String::from_utf8_lossy(&secret_key.stderr).to_string(),
            ));
        }

        Ok(Self {
            api_key: String::from_utf8_lossy(&api_key.stdout).trim().to_string(),
            secret_key: String::from_utf8_lossy(&secret_key.stdout)
                .trim()
                .to_string(),
        })
    }
}

#[derive(Serialize)]
struct AuthBody {
    apikey: String,
    secretapikey: String,
}

#[derive(Serialize)]
struct CreateRecordBody {
    apikey: String,
    secretapikey: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prio: Option<u32>,
}

#[derive(Serialize)]
struct UpdateRecordBody {
    apikey: String,
    secretapikey: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prio: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ApiResponse<T> {
    pub status: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(flatten)]
    pub data: Option<T>,
}

/// Response wrapper for DNS record list endpoint.
#[derive(Debug, Deserialize)]
pub struct DnsRecordsResponse {
    pub records: Vec<DnsRecord>,
}

/// A DNS record from the Porkbun API.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct DnsRecord {
    /// Unique identifier for this record (used for update/delete operations)
    pub id: String,
    /// Full record name (e.g., "www.example.com" or "example.com" for root)
    pub name: String,
    /// Record type: A, AAAA, CNAME, MX, TXT, NS, SRV, TLSA, CAA
    #[serde(rename = "type")]
    pub record_type: String,
    /// Record content (IP address, hostname, or text value)
    pub content: String,
    /// Time-to-live in seconds
    pub ttl: String,
    /// Priority (only set for MX and SRV records)
    #[serde(default)]
    pub prio: Option<String>,
    /// Optional notes attached to the record
    #[serde(default)]
    pub notes: Option<String>,
}

/// Response from creating a new DNS record.
#[derive(Debug, Deserialize)]
pub struct CreateRecordResponse {
    /// The ID of the newly created record
    pub id: u64,
}

/// Response from the ping endpoint, used to verify API connectivity.
#[derive(Debug, Deserialize)]
pub struct PingResponse {
    /// The IP address the API sees for your request
    #[serde(rename = "yourIp")]
    pub your_ip: String,
}

/// SSL certificate bundle for a domain.
#[derive(Debug, Deserialize)]
pub struct SslResponse {
    /// The full certificate chain (including intermediate certificates)
    #[serde(rename = "certificatechain")]
    pub certificate_chain: String,
    /// The private key for the certificate
    #[serde(rename = "privatekey")]
    pub private_key: String,
    /// The public key for the certificate
    #[serde(rename = "publickey")]
    pub public_key: String,
}

/// Response wrapper for pricing endpoint.
#[derive(Debug, Deserialize)]
pub struct PricingResponse {
    pub pricing: std::collections::HashMap<String, TldPricing>,
}

/// Domain availability check result.
#[derive(Debug, Deserialize)]
pub struct DomainCheckResponse {
    /// Whether the domain is available for registration
    #[serde(default)]
    pub avail: Option<bool>,
    /// Registration price in USD (only set if available)
    #[serde(default)]
    pub price: Option<String>,
    /// Whether this is a premium domain with special pricing
    #[serde(default)]
    pub premium: Option<bool>,
    /// Annual renewal price in USD (only set if available)
    #[serde(rename = "renewalPrice", default)]
    pub renewal_price: Option<String>,
}

/// Pricing information for a TLD (top-level domain).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TldPricing {
    /// Registration price in USD
    pub registration: String,
    /// Annual renewal price in USD
    pub renewal: String,
    /// Transfer price in USD
    pub transfer: String,
    /// Available coupon codes (if any)
    #[serde(default)]
    pub coupons: Option<serde_json::Value>,
}

/// Client for interacting with the Porkbun API.
///
/// Provides methods for domain availability checking, DNS management,
/// SSL certificate retrieval, and pricing information.
pub struct PorkbunClient {
    client: Client,
    credentials: Credentials,
}

impl PorkbunClient {
    /// Create a new client with the given credentials.
    pub fn new(credentials: Credentials) -> Self {
        Self {
            client: Client::new(),
            credentials,
        }
    }

    fn auth_body(&self) -> AuthBody {
        AuthBody {
            apikey: self.credentials.api_key.clone(),
            secretapikey: self.credentials.secret_key.clone(),
        }
    }

    /// Verify API connectivity and authentication.
    ///
    /// Returns your IP address as seen by the Porkbun API.
    /// This is useful for testing credentials before other operations.
    pub async fn ping(&self) -> Result<PingResponse, PorkbunError> {
        let resp: ApiResponse<PingResponse> = self
            .client
            .post(format!("{API_BASE}/ping"))
            .json(&self.auth_body())
            .send()
            .await?
            .json()
            .await?;

        if resp.status != "SUCCESS" {
            return Err(PorkbunError::Api(
                resp.message.unwrap_or_else(|| "Unknown error".to_string()),
            ));
        }

        resp.data
            .ok_or_else(|| PorkbunError::Api("No data in response".to_string()))
    }

    /// List all DNS records for a domain.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to list records for (e.g., "example.com")
    ///
    /// # Returns
    ///
    /// A list of all DNS records, or an empty list if none exist.
    pub async fn list_records(&self, domain: &str) -> Result<Vec<DnsRecord>, PorkbunError> {
        let resp: ApiResponse<DnsRecordsResponse> = self
            .client
            .post(format!("{API_BASE}/dns/retrieve/{domain}"))
            .json(&self.auth_body())
            .send()
            .await?
            .json()
            .await?;

        if resp.status != "SUCCESS" {
            return Err(PorkbunError::Api(
                resp.message.unwrap_or_else(|| "Unknown error".to_string()),
            ));
        }

        Ok(resp.data.map(|d| d.records).unwrap_or_default())
    }

    /// Create a new DNS record.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to create the record for (e.g., "example.com")
    /// * `record_type` - Record type: A, AAAA, CNAME, MX, TXT, NS, SRV, TLSA, CAA
    /// * `content` - Record content (IP address, hostname, or text value)
    /// * `name` - Subdomain name, or None for root/apex record
    /// * `ttl` - Time-to-live in seconds (default: 600)
    /// * `prio` - Priority (required for MX records, lower = higher priority)
    ///
    /// # Returns
    ///
    /// The ID of the newly created record.
    pub async fn create_record(
        &self,
        domain: &str,
        record_type: &str,
        content: &str,
        name: Option<&str>,
        ttl: Option<u32>,
        prio: Option<u32>,
    ) -> Result<u64, PorkbunError> {
        let body = CreateRecordBody {
            apikey: self.credentials.api_key.clone(),
            secretapikey: self.credentials.secret_key.clone(),
            record_type: record_type.to_string(),
            content: content.to_string(),
            name: name.map(|s| s.to_string()),
            ttl,
            prio,
        };

        let resp: ApiResponse<CreateRecordResponse> = self
            .client
            .post(format!("{API_BASE}/dns/create/{domain}"))
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if resp.status != "SUCCESS" {
            return Err(PorkbunError::Api(
                resp.message.unwrap_or_else(|| "Unknown error".to_string()),
            ));
        }

        resp.data
            .map(|d| d.id)
            .ok_or_else(|| PorkbunError::Api("No ID in response".to_string()))
    }

    /// Update an existing DNS record.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain the record belongs to
    /// * `record_id` - The record ID (from list_records output)
    /// * `record_type` - Record type: A, AAAA, CNAME, MX, TXT, NS, SRV, TLSA, CAA
    /// * `content` - New record content
    /// * `name` - Subdomain name, or None for root/apex record
    /// * `ttl` - Time-to-live in seconds
    /// * `prio` - Priority (for MX records)
    #[allow(clippy::too_many_arguments)]
    pub async fn update_record(
        &self,
        domain: &str,
        record_id: &str,
        record_type: &str,
        content: &str,
        name: Option<&str>,
        ttl: Option<u32>,
        prio: Option<u32>,
    ) -> Result<(), PorkbunError> {
        let body = UpdateRecordBody {
            apikey: self.credentials.api_key.clone(),
            secretapikey: self.credentials.secret_key.clone(),
            record_type: record_type.to_string(),
            content: content.to_string(),
            name: name.map(|s| s.to_string()),
            ttl,
            prio,
        };

        let resp: ApiResponse<()> = self
            .client
            .post(format!("{API_BASE}/dns/edit/{domain}/{record_id}"))
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if resp.status != "SUCCESS" {
            return Err(PorkbunError::Api(
                resp.message.unwrap_or_else(|| "Unknown error".to_string()),
            ));
        }

        Ok(())
    }

    /// Delete a DNS record.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain the record belongs to
    /// * `record_id` - The record ID to delete (from list_records output)
    pub async fn delete_record(&self, domain: &str, record_id: &str) -> Result<(), PorkbunError> {
        let resp: ApiResponse<()> = self
            .client
            .post(format!("{API_BASE}/dns/delete/{domain}/{record_id}"))
            .json(&self.auth_body())
            .send()
            .await?
            .json()
            .await?;

        if resp.status != "SUCCESS" {
            return Err(PorkbunError::Api(
                resp.message.unwrap_or_else(|| "Unknown error".to_string()),
            ));
        }

        Ok(())
    }

    /// Get the SSL certificate bundle for a domain.
    ///
    /// Retrieves the SSL certificate that Porkbun provisions for your domain.
    /// The domain must be registered with Porkbun and have SSL enabled.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to get the SSL bundle for
    ///
    /// # Returns
    ///
    /// The certificate chain, private key, and public key.
    pub async fn get_ssl(&self, domain: &str) -> Result<SslResponse, PorkbunError> {
        let resp: ApiResponse<SslResponse> = self
            .client
            .post(format!("{API_BASE}/ssl/retrieve/{domain}"))
            .json(&self.auth_body())
            .send()
            .await?
            .json()
            .await?;

        if resp.status != "SUCCESS" {
            return Err(PorkbunError::Api(
                resp.message.unwrap_or_else(|| "Unknown error".to_string()),
            ));
        }

        resp.data
            .ok_or_else(|| PorkbunError::Api("No SSL data in response".to_string()))
    }

    /// Get pricing information for all TLDs.
    ///
    /// Returns registration, renewal, and transfer prices for each TLD.
    pub async fn get_pricing(
        &self,
    ) -> Result<std::collections::HashMap<String, TldPricing>, PorkbunError> {
        let resp: ApiResponse<PricingResponse> = self
            .client
            .post(format!("{API_BASE}/pricing/get"))
            .json(&self.auth_body())
            .send()
            .await?
            .json()
            .await?;

        if resp.status != "SUCCESS" {
            return Err(PorkbunError::Api(
                resp.message.unwrap_or_else(|| "Unknown error".to_string()),
            ));
        }

        Ok(resp.data.map(|d| d.pricing).unwrap_or_default())
    }

    /// Check if a domain is available for registration.
    ///
    /// Returns availability status, pricing (if available), and whether
    /// it's a premium domain.
    ///
    /// # Arguments
    ///
    /// * `domain` - The full domain to check (e.g., "example.com")
    ///
    /// # Rate Limiting
    ///
    /// Domain checks are rate limited by Porkbun. You will be notified
    /// of your limit when you cross it.
    pub async fn check_domain(&self, domain: &str) -> Result<DomainCheckResponse, PorkbunError> {
        let resp: ApiResponse<DomainCheckResponse> = self
            .client
            .post(format!("{API_BASE}/domain/checkDomain/{domain}"))
            .json(&self.auth_body())
            .send()
            .await?
            .json()
            .await?;

        if resp.status != "SUCCESS" {
            return Err(PorkbunError::Api(
                resp.message.unwrap_or_else(|| "Unknown error".to_string()),
            ));
        }

        resp.data
            .ok_or_else(|| PorkbunError::Api("No data in response".to_string()))
    }
}
