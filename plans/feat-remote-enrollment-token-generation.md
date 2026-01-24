# feat: Remote Enrollment Token Generation with Rate Limiting

## Overview

Add remote enrollment token generation capability to Continuum, allowing enrolled CLIs to request enrollment tokens from a daemon through the relay. Includes rate limiting to maximum 3 concurrent live tokens per daemon.

**Scope:** Any enrolled client (verified via mTLS) can generate tokens. No additional authorization layer.

## Problem Statement

**Current Flow (requires local access):**
```
Admin (on daemon machine)          User (remote)
    |                                   |
    |--$ continuum-daemon token generate --label "alice" --validity 5m
    |                                   |
    |--[shares token via email/slack]-->|
    |                                   |--$ continuum enroll <token>
```

**Pain Points:**
- Must SSH into daemon machine to generate tokens
- Breaks self-service model for distributed teams

**Proposed Flow (remote):**
```
Enrolled CLI                Relay                    Daemon
    |                         |                         |
    |--$ continuum generate-token --daemon <fp>         |
    |------ mTLS auth --------------------------------->|
    |                         |                         |--1. Verify mTLS cert is enrolled
    |                         |                         |--2. Check live token count < 3
    |                         |                         |--3. Generate & store token
    |<----- Token response -----------------------------|
```

## Proposed Solution

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLI (Enrolled)                                  │
│            continuum generate-token --daemon <fingerprint>                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼ mTLS via relay
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Daemon                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ EnrollmentService::RequestEnrollmentToken()                          │   │
│  │   1. require_authenticated() - verify client has valid mTLS cert     │   │
│  │   2. Atomic INSERT with rate limit check (max 3 live tokens)         │   │
│  │   3. Return token string                                             │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ SQLite: enrollment_tokens                                            │   │
│  │   Live token = expires_at > now AND used_at IS NULL                  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Rate Limiting

- **Limit:** 3 concurrent live tokens per daemon
- **Live token:** `expires_at > now AND used_at IS NULL`
- **Token becomes non-live when:** consumed OR expires
- **Error:** `RESOURCE_EXHAUSTED` when limit reached
- **Atomic:** Single-statement INSERT with subquery to prevent race conditions

## Technical Approach

### Phase 1: Protobuf Definition

**File:** `continuum-proto/proto/enrollment.proto`

```protobuf
// Add to existing EnrollmentService
service EnrollmentService {
  // ... existing RPCs ...

  // Request a new enrollment token (requires mTLS auth, rate limited)
  rpc RequestEnrollmentToken(RequestEnrollmentTokenRequest)
      returns (RequestEnrollmentTokenResponse);
}

message RequestEnrollmentTokenRequest {
  string label = 1;  // Optional human-readable label
}

message RequestEnrollmentTokenResponse {
  string token = 1;           // Base64 signed token
  int64 expires_at_unix = 2;  // Expiration timestamp
}
```

### Phase 2: Auth Store Extension

**File:** `continuum-daemon/src/auth/store.rs`

```rust
/// Atomically create token if under rate limit.
/// Uses single INSERT with subquery to prevent race conditions.
pub async fn create_token_with_rate_limit(
    &self,
    token_hash: &str,
    label: Option<&str>,
    expires_at: i64,
    max_live_tokens: i32,
) -> Result<(), AuthStoreError> {
    let now = current_timestamp();

    // Single atomic INSERT - no TOCTOU race possible
    let result = sqlx::query(
        "INSERT INTO enrollment_tokens (token_hash, label, created_at, expires_at)
         SELECT ?, ?, ?, ?
         WHERE (SELECT COUNT(*) FROM enrollment_tokens
                WHERE used_at IS NULL AND expires_at > ?) < ?"
    )
    .bind(token_hash)
    .bind(label)
    .bind(now)
    .bind(expires_at)
    .bind(now)
    .bind(max_live_tokens)
    .execute(&self.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AuthStoreError::RateLimitExceeded);
    }
    Ok(())
}
```

**Add error variant:**
```rust
#[derive(Debug, thiserror::Error)]
pub enum AuthStoreError {
    #[error("token already used")]
    TokenAlreadyUsed,
    #[error("rate limit exceeded: maximum live tokens reached")]
    RateLimitExceeded,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}
```

### Phase 3: Enrollment Service Implementation

**File:** `continuum-daemon/src/services/enrollment.rs`

```rust
const MAX_LIVE_TOKENS: i32 = 3;
const DEFAULT_VALIDITY_SECONDS: i64 = 300; // 5 minutes

#[tonic::async_trait]
impl EnrollmentService for EnrollmentServiceImpl {
    async fn request_enrollment_token(
        &self,
        request: Request<RequestEnrollmentTokenRequest>,
    ) -> Result<Response<RequestEnrollmentTokenResponse>, Status> {
        // 1. Require mTLS authentication (client must be enrolled)
        self.require_authenticated(&request)?;

        let req = request.into_inner();

        // 2. Generate signed token (hardcoded 5 min validity for simplicity)
        let token = SignedEnrollmentToken::generate(
            &self.identity.secret_key,
            &self.identity.fingerprint,
            chrono::Duration::seconds(DEFAULT_VALIDITY_SECONDS),
        );

        let token_hash = hash_token(&token.to_base64());
        let expires_at = token.expires_at_unix();

        // 3. Atomic insert with rate limit check
        self.auth_store
            .create_token_with_rate_limit(
                &token_hash,
                if req.label.is_empty() { None } else { Some(&req.label) },
                expires_at,
                MAX_LIVE_TOKENS,
            )
            .await
            .map_err(|e| match e {
                AuthStoreError::RateLimitExceeded => {
                    Status::resource_exhausted(
                        "Rate limit reached: 3 live tokens maximum. Wait for tokens to expire or be used."
                    )
                }
                _ => Status::internal(format!("Failed to store token: {}", e)),
            })?;

        tracing::info!(
            label = %req.label,
            expires_at = %expires_at,
            "Enrollment token created remotely"
        );

        Ok(Response::new(RequestEnrollmentTokenResponse {
            token: token.to_base64(),
            expires_at_unix: expires_at,
        }))
    }
}
```

### Phase 4: CLI Command

**File:** `continuum-cli/src/main.rs` (add to Commands enum)

```rust
#[derive(Subcommand)]
enum Commands {
    // ... existing commands ...

    /// Generate an enrollment token for a daemon (requires enrollment)
    GenerateToken {
        /// Target daemon fingerprint
        #[arg(long)]
        daemon: String,

        /// Human-readable label for the token
        #[arg(long, short)]
        label: Option<String>,
    },
}
```

**File:** `continuum-cli/src/commands/generate_token.rs` (new file)

```rust
use anyhow::{Context, Result};
use continuum_proto::enrollment::v1::{
    enrollment_service_client::EnrollmentServiceClient,
    RequestEnrollmentTokenRequest,
};

pub async fn cmd_generate_token(
    daemon_fingerprint: &str,
    label: Option<&str>,
) -> Result<()> {
    // Connect via mTLS (reuses existing authenticated channel logic)
    let channel = connect_authenticated_channel().await?;
    let mut client = EnrollmentServiceClient::new(channel);

    let request = RequestEnrollmentTokenRequest {
        label: label.unwrap_or("").to_string(),
    };

    // Route to specific daemon via relay metadata
    let mut request = tonic::Request::new(request);
    request.metadata_mut().insert(
        "x-target-daemon",
        daemon_fingerprint.parse().context("Invalid daemon fingerprint")?,
    );

    let response = client
        .request_enrollment_token(request)
        .await
        .context("Failed to request enrollment token")?
        .into_inner();

    println!("Enrollment token generated:");
    println!();
    println!("  {}", response.token);
    println!();
    println!("Expires: {}", format_timestamp(response.expires_at_unix));
    println!();
    println!("Share with user to enroll:");
    println!("  continuum enroll {}", response.token);

    Ok(())
}
```

## Acceptance Criteria

### Functional
- [ ] Enrolled CLI can generate token via `continuum generate-token --daemon <fp>`
- [ ] Token generation fails with `RESOURCE_EXHAUSTED` when 3 live tokens exist
- [ ] Generated tokens work with existing `continuum enroll <token>` flow
- [ ] Only mTLS-authenticated (enrolled) clients can generate tokens

### Rate Limiting
- [ ] Maximum 3 live tokens per daemon
- [ ] Concurrent requests handled atomically (no race conditions)
- [ ] Token becomes non-live when consumed or expires

### Security
- [ ] Requires mTLS authentication (existing `require_authenticated()`)
- [ ] No Auth0/JWT involvement - purely mTLS-based
- [ ] Tokens are single-use and short-lived (5 min)

## Files to Modify

| File | Change |
|------|--------|
| `continuum-proto/proto/enrollment.proto` | Add `RequestEnrollmentToken` RPC |
| `continuum-daemon/src/auth/store.rs` | Add `create_token_with_rate_limit()`, `RateLimitExceeded` error |
| `continuum-daemon/src/services/enrollment.rs` | Implement `request_enrollment_token()` |
| `continuum-cli/src/main.rs` | Add `GenerateToken` command |
| `continuum-cli/src/commands/generate_token.rs` | New file for command implementation |

## Testing

### Unit Tests
- `auth/store.rs`: Test `create_token_with_rate_limit` returns error at limit

### Integration Tests
- Rate limit: Create 3 tokens successfully, 4th fails
- Token consumption frees slot
- Token expiration frees slot
- Concurrent requests don't exceed limit

## What's NOT Included (Deferred)

- Token listing (`ListLiveTokens`) - admin knows what they created
- Token cancellation (`CancelEnrollmentToken`) - tokens expire in 5 min
- Audit trail (`created_by_fingerprint`) - add when needed
- Configurable validity - hardcoded to 5 min for simplicity
- JSON output - add when scripting use case arises
