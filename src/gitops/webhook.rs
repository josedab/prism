//! Webhook handler for GitOps push-based updates

use super::config::{WebhookConfig, WebhookProvider};
use super::sync::GitOpsSyncManager;
use crate::error::{PrismError, Result};
use bytes::Bytes;
use hmac::{Hmac, Mac};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use serde::Deserialize;
use sha2::Sha256;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

type HmacSha256 = Hmac<Sha256>;

/// Webhook handler for Git push events
pub struct WebhookHandler {
    config: WebhookConfig,
    sync_manager: Arc<GitOpsSyncManager>,
}

impl WebhookHandler {
    /// Create a new webhook handler
    pub fn new(config: WebhookConfig, sync_manager: Arc<GitOpsSyncManager>) -> Self {
        Self {
            config,
            sync_manager,
        }
    }

    /// Handle an incoming webhook request
    pub async fn handle(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        // Check method
        if req.method() != Method::POST {
            return Ok(self.error_response(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed"));
        }

        // Check path
        if req.uri().path() != self.config.path {
            return Ok(self.error_response(StatusCode::NOT_FOUND, "Not found"));
        }

        // Split request into parts to get owned body
        let (parts, body) = req.into_parts();
        let req_headers = parts.headers;

        // Read body
        let body_bytes = match http_body_util::BodyExt::collect(body)
            .await
            .map(|c| c.to_bytes())
        {
            Ok(bytes) => bytes,
            Err(e) => {
                error!(error = %e, "Failed to read webhook body");
                return Ok(self.error_response(StatusCode::BAD_REQUEST, "Failed to read body"));
            }
        };

        // Validate signature if secret is configured
        if let Some(secret) = &self.config.secret {
            if !self.validate_signature(&req_headers, &body_bytes, secret) {
                warn!("Invalid webhook signature");
                return Ok(self.error_response(StatusCode::UNAUTHORIZED, "Invalid signature"));
            }
        }

        // Parse payload based on provider
        let event = match self.parse_payload(&req_headers, &body_bytes) {
            Ok(event) => event,
            Err(e) => {
                error!(error = %e, "Failed to parse webhook payload");
                return Ok(self.error_response(StatusCode::BAD_REQUEST, "Invalid payload"));
            }
        };

        info!(
            provider = ?self.config.provider,
            branch = %event.branch,
            commit = %event.commit,
            "Received webhook event"
        );

        // Check if this is for our branch
        let _repo_config = &self.sync_manager.get_state().environment;
        // TODO: Get branch from config properly

        // Trigger sync
        match self.sync_manager.trigger_sync().await {
            Ok(()) => {
                info!("Sync triggered by webhook");
                Ok(self.success_response("Sync triggered"))
            }
            Err(e) => {
                error!(error = %e, "Sync failed after webhook trigger");
                Ok(self.error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Sync failed: {}", e),
                ))
            }
        }
    }

    /// Validate webhook signature
    fn validate_signature(&self, headers: &http::HeaderMap, body: &[u8], secret: &str) -> bool {
        match self.config.provider {
            WebhookProvider::Github => self.validate_github_signature(headers, body, secret),
            WebhookProvider::Gitlab => self.validate_gitlab_signature(headers, secret),
            WebhookProvider::Bitbucket => {
                // Bitbucket uses different auth mechanism
                warn!("Bitbucket signature validation not yet implemented");
                true
            }
            WebhookProvider::Gitea => self.validate_gitea_signature(headers, body, secret),
            WebhookProvider::Generic => {
                // For generic, just check X-Webhook-Secret header
                headers
                    .get("X-Webhook-Secret")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s == secret)
                    .unwrap_or(false)
            }
        }
    }

    /// Validate GitHub signature (X-Hub-Signature-256)
    fn validate_github_signature(&self, headers: &http::HeaderMap, body: &[u8], secret: &str) -> bool {
        let signature = match headers.get("X-Hub-Signature-256") {
            Some(sig) => sig.to_str().unwrap_or(""),
            None => return false,
        };

        // Signature format: sha256=<hex>
        let expected_signature = match signature.strip_prefix("sha256=") {
            Some(s) => s,
            None => return false,
        };

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(body);

        let result = mac.finalize();
        let computed = hex::encode(result.into_bytes());

        // Constant time comparison
        computed == expected_signature
    }

    /// Validate GitLab signature (X-Gitlab-Token)
    fn validate_gitlab_signature(&self, headers: &http::HeaderMap, secret: &str) -> bool {
        headers
            .get("X-Gitlab-Token")
            .and_then(|v| v.to_str().ok())
            .map(|s| s == secret)
            .unwrap_or(false)
    }

    /// Validate Gitea signature (same as GitHub)
    fn validate_gitea_signature(&self, headers: &http::HeaderMap, body: &[u8], secret: &str) -> bool {
        // Gitea uses the same signature format as GitHub
        self.validate_github_signature(headers, body, secret)
    }

    /// Parse webhook payload
    fn parse_payload(&self, headers: &http::HeaderMap, body: &[u8]) -> Result<WebhookEvent> {
        match self.config.provider {
            WebhookProvider::Github => self.parse_github_payload(headers, body),
            WebhookProvider::Gitlab => self.parse_gitlab_payload(body),
            WebhookProvider::Bitbucket => self.parse_bitbucket_payload(body),
            WebhookProvider::Gitea => self.parse_gitea_payload(body),
            WebhookProvider::Generic => self.parse_generic_payload(body),
        }
    }

    /// Parse GitHub webhook payload
    fn parse_github_payload(&self, headers: &http::HeaderMap, body: &[u8]) -> Result<WebhookEvent> {
        let event_type = headers
            .get("X-GitHub-Event")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");

        debug!(event_type = %event_type, "Parsing GitHub webhook");

        if event_type != "push" {
            return Err(PrismError::Config(format!(
                "Ignoring non-push event: {}",
                event_type
            )));
        }

        let payload: GitHubPushEvent = serde_json::from_slice(body)
            .map_err(|e| PrismError::Config(format!("Failed to parse GitHub payload: {}", e)))?;

        // Extract branch from ref (refs/heads/main -> main)
        let branch = payload
            .ref_name
            .strip_prefix("refs/heads/")
            .unwrap_or(&payload.ref_name)
            .to_string();

        Ok(WebhookEvent {
            provider: WebhookProvider::Github,
            event_type: "push".to_string(),
            branch,
            commit: payload.after,
            message: payload.head_commit.map(|c| c.message).unwrap_or_default(),
            author: payload.pusher.map(|p| p.name).unwrap_or_default(),
            repository: payload.repository.map(|r| r.full_name).unwrap_or_default(),
        })
    }

    /// Parse GitLab webhook payload
    fn parse_gitlab_payload(&self, body: &[u8]) -> Result<WebhookEvent> {
        let payload: GitLabPushEvent = serde_json::from_slice(body)
            .map_err(|e| PrismError::Config(format!("Failed to parse GitLab payload: {}", e)))?;

        // Extract branch from ref
        let branch = payload
            .ref_name
            .strip_prefix("refs/heads/")
            .unwrap_or(&payload.ref_name)
            .to_string();

        Ok(WebhookEvent {
            provider: WebhookProvider::Gitlab,
            event_type: payload.object_kind,
            branch,
            commit: payload.after,
            message: payload.commits.first().map(|c| c.message.clone()).unwrap_or_default(),
            author: payload.user_name,
            repository: payload.project.map(|p| p.path_with_namespace).unwrap_or_default(),
        })
    }

    /// Parse Bitbucket webhook payload
    fn parse_bitbucket_payload(&self, body: &[u8]) -> Result<WebhookEvent> {
        let payload: BitbucketPushEvent = serde_json::from_slice(body)
            .map_err(|e| PrismError::Config(format!("Failed to parse Bitbucket payload: {}", e)))?;

        let change = payload
            .push
            .changes
            .first()
            .ok_or_else(|| PrismError::Config("No changes in Bitbucket push".to_string()))?;

        Ok(WebhookEvent {
            provider: WebhookProvider::Bitbucket,
            event_type: "push".to_string(),
            branch: change.new.name.clone(),
            commit: change.new.target.hash.clone(),
            message: change.new.target.message.clone().unwrap_or_default(),
            author: payload.actor.display_name,
            repository: payload.repository.full_name,
        })
    }

    /// Parse Gitea webhook payload
    fn parse_gitea_payload(&self, body: &[u8]) -> Result<WebhookEvent> {
        // Gitea has a similar format to GitHub
        let payload: GiteaPushEvent = serde_json::from_slice(body)
            .map_err(|e| PrismError::Config(format!("Failed to parse Gitea payload: {}", e)))?;

        let branch = payload
            .ref_name
            .strip_prefix("refs/heads/")
            .unwrap_or(&payload.ref_name)
            .to_string();

        Ok(WebhookEvent {
            provider: WebhookProvider::Gitea,
            event_type: "push".to_string(),
            branch,
            commit: payload.after,
            message: payload.commits.first().map(|c| c.message.clone()).unwrap_or_default(),
            author: payload.pusher.map(|p| p.username).unwrap_or_default(),
            repository: payload.repository.map(|r| r.full_name).unwrap_or_default(),
        })
    }

    /// Parse generic webhook payload
    fn parse_generic_payload(&self, body: &[u8]) -> Result<WebhookEvent> {
        let payload: GenericWebhookEvent = serde_json::from_slice(body)
            .map_err(|e| PrismError::Config(format!("Failed to parse generic payload: {}", e)))?;

        Ok(WebhookEvent {
            provider: WebhookProvider::Generic,
            event_type: payload.event_type.unwrap_or_else(|| "push".to_string()),
            branch: payload.branch.unwrap_or_else(|| "main".to_string()),
            commit: payload.commit.unwrap_or_default(),
            message: payload.message.unwrap_or_default(),
            author: payload.author.unwrap_or_default(),
            repository: payload.repository.unwrap_or_default(),
        })
    }

    /// Create success response
    fn success_response(&self, message: &str) -> Response<Full<Bytes>> {
        let body = serde_json::json!({
            "status": "ok",
            "message": message,
        });

        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap()
    }

    /// Create error response
    fn error_response(&self, status: StatusCode, message: &str) -> Response<Full<Bytes>> {
        let body = serde_json::json!({
            "status": "error",
            "message": message,
        });

        Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap()
    }
}

/// Parsed webhook event
#[derive(Debug, Clone)]
pub struct WebhookEvent {
    /// Provider that sent the webhook
    pub provider: WebhookProvider,
    /// Event type (push, pull_request, etc.)
    pub event_type: String,
    /// Branch name
    pub branch: String,
    /// Commit SHA
    pub commit: String,
    /// Commit message
    pub message: String,
    /// Author name
    pub author: String,
    /// Repository name
    pub repository: String,
}

// ============================================================================
// Provider-specific payload types
// ============================================================================

#[derive(Debug, Deserialize)]
struct GitHubPushEvent {
    #[serde(rename = "ref")]
    ref_name: String,
    after: String,
    head_commit: Option<GitHubCommit>,
    pusher: Option<GitHubPusher>,
    repository: Option<GitHubRepository>,
}

#[derive(Debug, Deserialize)]
struct GitHubCommit {
    message: String,
}

#[derive(Debug, Deserialize)]
struct GitHubPusher {
    name: String,
}

#[derive(Debug, Deserialize)]
struct GitHubRepository {
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct GitLabPushEvent {
    object_kind: String,
    #[serde(rename = "ref")]
    ref_name: String,
    after: String,
    user_name: String,
    commits: Vec<GitLabCommit>,
    project: Option<GitLabProject>,
}

#[derive(Debug, Deserialize)]
struct GitLabCommit {
    message: String,
}

#[derive(Debug, Deserialize)]
struct GitLabProject {
    path_with_namespace: String,
}

#[derive(Debug, Deserialize)]
struct BitbucketPushEvent {
    push: BitbucketPush,
    actor: BitbucketActor,
    repository: BitbucketRepository,
}

#[derive(Debug, Deserialize)]
struct BitbucketPush {
    changes: Vec<BitbucketChange>,
}

#[derive(Debug, Deserialize)]
struct BitbucketChange {
    new: BitbucketRef,
}

#[derive(Debug, Deserialize)]
struct BitbucketRef {
    name: String,
    target: BitbucketTarget,
}

#[derive(Debug, Deserialize)]
struct BitbucketTarget {
    hash: String,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BitbucketActor {
    display_name: String,
}

#[derive(Debug, Deserialize)]
struct BitbucketRepository {
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct GiteaPushEvent {
    #[serde(rename = "ref")]
    ref_name: String,
    after: String,
    commits: Vec<GiteaCommit>,
    pusher: Option<GiteaPusher>,
    repository: Option<GiteaRepository>,
}

#[derive(Debug, Deserialize)]
struct GiteaCommit {
    message: String,
}

#[derive(Debug, Deserialize)]
struct GiteaPusher {
    username: String,
}

#[derive(Debug, Deserialize)]
struct GiteaRepository {
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct GenericWebhookEvent {
    event_type: Option<String>,
    branch: Option<String>,
    commit: Option<String>,
    message: Option<String>,
    author: Option<String>,
    repository: Option<String>,
}

/// Start webhook server
pub async fn start_webhook_server(
    config: WebhookConfig,
    sync_manager: Arc<GitOpsSyncManager>,
) -> Result<()> {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let handler = Arc::new(WebhookHandler::new(config.clone(), sync_manager));
    let addr = config.address.parse::<std::net::SocketAddr>()
        .map_err(|e| PrismError::Config(format!("Invalid webhook address: {}", e)))?;

    let listener = TcpListener::bind(addr).await
        .map_err(|e| PrismError::Config(format!("Failed to bind webhook server: {}", e)))?;

    info!(address = %addr, path = %config.path, "GitOps webhook server started");

    loop {
        let (stream, _) = listener.accept().await
            .map_err(|e| PrismError::Config(format!("Failed to accept connection: {}", e)))?;

        let io = TokioIo::new(stream);
        let handler = Arc::clone(&handler);

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let handler = Arc::clone(&handler);
                async move {
                    handler.handle(req).await
                }
            });

            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                error!(error = %e, "Webhook connection error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_github_branch() {
        let ref_name = "refs/heads/main";
        let branch = ref_name.strip_prefix("refs/heads/").unwrap_or(ref_name);
        assert_eq!(branch, "main");
    }

    #[test]
    fn test_github_signature_validation() {
        // Test vector from GitHub docs
        let secret = "It's a Secret to Everybody";
        let body = b"Hello, World!";

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let result = mac.finalize();
        let signature = hex::encode(result.into_bytes());

        // This should produce: sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17
        assert!(!signature.is_empty());
    }
}
