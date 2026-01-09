use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const API_BASE: &str = "https://api.porkbun.com/api/json/v3";

#[derive(Error, Debug)]
pub enum PorkbunError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API error: {0}")]
    Api(String),
    #[error("Failed to get credentials: {0}")]
    Credentials(String),
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub api_key: String,
    pub secret_key: String,
}

impl Credentials {
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

#[derive(Debug, Deserialize)]
pub struct DnsRecordsResponse {
    pub records: Vec<DnsRecord>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    pub ttl: String,
    #[serde(default)]
    pub prio: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRecordResponse {
    pub id: u64,
}

#[derive(Debug, Deserialize)]
pub struct PingResponse {
    #[serde(rename = "yourIp")]
    pub your_ip: String,
}

#[derive(Debug, Deserialize)]
pub struct SslResponse {
    #[serde(rename = "certificatechain")]
    pub certificate_chain: String,
    #[serde(rename = "privatekey")]
    pub private_key: String,
    #[serde(rename = "publickey")]
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct PricingResponse {
    pub pricing: std::collections::HashMap<String, TldPricing>,
}

#[derive(Debug, Deserialize)]
pub struct DomainCheckResponse {
    #[serde(default)]
    pub avail: Option<bool>,
    #[serde(default)]
    pub price: Option<String>,
    #[serde(default)]
    pub premium: Option<bool>,
    #[serde(rename = "renewalPrice", default)]
    pub renewal_price: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TldPricing {
    pub registration: String,
    pub renewal: String,
    pub transfer: String,
    #[serde(default)]
    pub coupons: Option<serde_json::Value>,
}

pub struct PorkbunClient {
    client: Client,
    credentials: Credentials,
}

impl PorkbunClient {
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
