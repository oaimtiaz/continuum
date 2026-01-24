# feat: Enforce Billing/Plan Limits in Relay

## Overview

Add plan limit enforcement to the Continuum relay service so that free, pro, team, and enterprise tiers have appropriate resource constraints. Currently, the relay accepts unlimited daemons and sessions regardless of user plan.

**Plan Definitions (from dashboard):**

| Plan | maxHosts | maxSessions | sessionTimeoutMinutes |
|------|----------|-------------|----------------------|
| Free | 1 | 2 | 15 |
| Pro | 5 | unlimited (-1) | unlimited (-1) |
| Team | unlimited (-1) | unlimited (-1) | unlimited (-1) |
| Enterprise | unlimited (-1) | unlimited (-1) | unlimited (-1) |

**Important Clarification:**
- **Daemons (hosts)** can stay connected indefinitely regardless of plan - no timeout on daemon connections
- **Client sessions** (tunnels/interactive sessions) face the `sessionTimeoutMinutes` limit
- `-1` means unlimited (no limit/no timeout)

## Problem Statement

The relay currently has **no plan limit enforcement**. Any authenticated user can:
- Connect unlimited daemons (hosts)
- Create unlimited concurrent sessions
- Run sessions indefinitely

This breaks the billing model and allows free tier abuse.

## Proposed Solution

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Auth0                                                                    │
│                                                                          │
│  Post-Login Action injects plan limits into JWT claims:                 │
│  {                                                                       │
│    "https://continuum.dev/plan": "free",                                │
│    "https://continuum.dev/limits": {                                    │
│      "maxHosts": 1,                                                     │
│      "maxSessions": 2,                                                  │
│      "sessionTimeoutMinutes": 15                                        │
│    }                                                                     │
│  }                                                                       │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ JWT with limits
┌─────────────────────────────────────────────────────────────────────────┐
│ Relay Service                                                            │
│                                                                          │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐     │
│  │ accept_daemon() │    │ handle_session  │    │ session timeout │     │
│  │                 │    │ _request()      │    │ (spawned task)  │     │
│  │ Check maxHosts  │    │ Check maxSess.  │    │ Check timeout   │     │
│  │ NO TIMEOUT      │    │ + spawn timeout │    │ on CLIENT only  │     │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘     │
│           │                      │                      │              │
│           ▼                      ▼                      ▼              │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ DaemonRegistry          SessionRegistry                          │   │
│  │ - try_insert_by_user()  - try_insert_by_user()                   │   │
│  │ - Atomic check-and-add  - Atomic check-and-add                   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Enforcement Points

| Point | File | Function | Limit | Behavior |
|-------|------|----------|-------|----------|
| Daemon connect | `src/daemon/connection.rs` | `accept_daemon()` | maxHosts | Reject with RESOURCE_EXHAUSTED |
| Session create | `src/session/mod.rs` | `handle_session_request()` | maxSessions | Reject with RESOURCE_EXHAUSTED |
| Active session | `src/session/mod.rs` | spawned timeout task | sessionTimeoutMinutes | Warn at T-2min, disconnect at T |

**Note:** Daemons have NO timeout - they can stay connected indefinitely. Only client sessions (tunnels) are subject to timeout.

## Technical Approach

### Phase 1: Add Plan Limits to JWT Claims

**Auth0 Action (already exists at `/api/auth/user-claims`):**

Update to include limits in the response:

```typescript
// apps/dashboard/app/api/auth/user-claims/route.ts
export async function GET(request: Request) {
  const userId = request.headers.get('x-auth0-user-id');

  const user = await supabase
    .from('users')
    .select('current_plan, plan_limits')
    .eq('id', userId)
    .single();

  return Response.json({
    plan: user.current_plan,
    limits: user.plan_limits,  // {maxHosts, maxSessions, sessionTimeoutMinutes}
    orgId: user.org_id,
  });
}
```

**Auth0 Action (Post-Login):**

```javascript
exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://continuum.dev';

  // Fetch user entitlements from dashboard API
  const response = await axios.get(
    `${event.secrets.DASHBOARD_API_URL}/api/auth/user-claims`,
    { headers: { 'x-auth0-user-id': event.user.user_id } }
  );

  const { plan, limits, orgId } = response.data;

  api.accessToken.setCustomClaim(`${namespace}/plan`, plan);
  api.accessToken.setCustomClaim(`${namespace}/limits`, limits);
  api.accessToken.setCustomClaim(`${namespace}/org_id`, orgId);
};
```

### Phase 2: Parse Limits in Relay

**File:** `src/auth.rs`

```rust
// Add to Claims struct
#[derive(Debug, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: Audience,
    pub exp: i64,
    pub iat: i64,

    #[serde(rename = "https://continuum.dev/org_id")]
    pub org_id: String,

    #[serde(rename = "https://continuum.dev/kind")]
    pub kind: TokenKind,

    #[serde(rename = "https://continuum.dev/fingerprint")]
    pub fingerprint: Option<String>,

    // NEW: Plan limits (with defaults for backward compatibility)
    #[serde(rename = "https://continuum.dev/plan", default = "default_plan")]
    pub plan: String,

    #[serde(rename = "https://continuum.dev/limits", default)]
    pub limits: PlanLimits,
}

fn default_plan() -> String {
    "free".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct PlanLimits {
    #[serde(rename = "maxHosts", default = "default_max_hosts")]
    pub max_hosts: i32,  // -1 = unlimited

    #[serde(rename = "maxSessions", default = "default_max_sessions")]
    pub max_sessions: i32,  // -1 = unlimited

    #[serde(rename = "sessionTimeoutMinutes", default = "default_session_timeout")]
    pub session_timeout_minutes: i32,  // -1 = no timeout
}

// Defaults to free tier limits for backward compatibility
fn default_max_hosts() -> i32 { 1 }
fn default_max_sessions() -> i32 { 2 }
fn default_session_timeout() -> i32 { 15 }

impl Default for PlanLimits {
    fn default() -> Self {
        Self {
            max_hosts: default_max_hosts(),
            max_sessions: default_max_sessions(),
            session_timeout_minutes: default_session_timeout(),
        }
    }
}

impl PlanLimits {
    pub fn is_unlimited_hosts(&self) -> bool {
        self.max_hosts < 0
    }

    pub fn is_unlimited_sessions(&self) -> bool {
        self.max_sessions < 0
    }

    pub fn has_session_timeout(&self) -> bool {
        self.session_timeout_minutes > 0
    }
}
```

### Phase 3: Add Atomic Registry Methods (Race Condition Fix)

**File:** `src/daemon/registry.rs`

```rust
impl DaemonRegistry {
    /// Atomically check limit and insert daemon.
    /// Returns Ok(()) if inserted, Err with current count if limit exceeded.
    pub fn try_insert_with_limit(
        &self,
        daemon: Daemon,
        user_id: &str,
        max_hosts: i32,
        fingerprint: &str,
    ) -> Result<(), usize> {
        // Use DashMap's entry API for atomic check-and-insert
        // Note: This is a simplified version - actual impl depends on DashMap structure

        // Allow reconnection of same fingerprint
        if self.get_by_fingerprint(fingerprint).is_some() {
            // Update existing entry instead of insert
            self.update_daemon(fingerprint, daemon);
            return Ok(());
        }

        // Check limit (-1 = unlimited)
        if max_hosts >= 0 {
            let current = self.count_by_user(user_id);
            if current >= max_hosts as usize {
                return Err(current);
            }
        }

        self.insert(daemon);
        Ok(())
    }

    /// Count online daemons for a specific user
    pub fn count_by_user(&self, user_id: &str) -> usize {
        self.daemons
            .iter()
            .filter(|entry| entry.user_id == user_id)
            .count()
    }
}
```

**File:** `src/session/registry.rs`

```rust
impl SessionRegistry {
    /// Atomically check limit and insert session.
    /// Returns Ok(()) if inserted, Err with current count if limit exceeded.
    pub fn try_insert_with_limit(
        &self,
        session: Session,
        user_id: &str,
        max_sessions: i32,
    ) -> Result<(), usize> {
        // Check limit (-1 = unlimited)
        if max_sessions >= 0 {
            let current = self.count_active_by_user(user_id);
            if current >= max_sessions as usize {
                return Err(current);
            }
        }

        self.insert(session);
        Ok(())
    }

    /// Count active sessions for a specific user
    pub fn count_active_by_user(&self, user_id: &str) -> usize {
        self.sessions
            .iter()
            .filter(|entry| {
                let session = entry.value();
                session.user_id == user_id && session.is_active()
            })
            .count()
    }
}
```

### Phase 4: Enforce Host Limit on Daemon Connect

**File:** `src/daemon/connection.rs`

```rust
// In accept_daemon(), after authentication

// Atomic check-and-insert with limit enforcement
if let Err(current) = state.daemons.try_insert_with_limit(
    daemon,
    &claims.sub,
    claims.limits.max_hosts,
    &fingerprint,
) {
    tracing::warn!(
        user_id = %claims.sub,
        current = current,
        limit = claims.limits.max_hosts,
        "Host limit exceeded"
    );

    return Err(RelayError::LimitExceeded(
        format!(
            "Host limit reached ({}/{}). Upgrade your plan for more hosts.",
            current,
            claims.limits.max_hosts
        )
    ));
}
```

### Phase 5: Enforce Session Limit + Timeout on Session Create

**File:** `src/session/mod.rs`

```rust
// In handle_session_request(), after authentication

// Atomic check-and-insert with limit enforcement
if let Err(current) = state.sessions.try_insert_with_limit(
    session,
    &claims.sub,
    claims.limits.max_sessions,
) {
    tracing::warn!(
        user_id = %claims.sub,
        current = current,
        limit = claims.limits.max_sessions,
        "Session limit exceeded"
    );

    return Err(RelayError::LimitExceeded(
        format!(
            "Session limit reached ({}/{}). Upgrade your plan for more sessions.",
            current,
            claims.limits.max_sessions
        )
    ));
}

// Spawn timeout task for client sessions (not daemons)
// Only if plan has a timeout (sessionTimeoutMinutes > 0)
if claims.limits.has_session_timeout() {
    let session_id = session_id.clone();
    let user_id = claims.sub.clone();
    let timeout_minutes = claims.limits.session_timeout_minutes;
    let shutdown_tx = shutdown_tx.clone();

    tokio::spawn(async move {
        let timeout = Duration::from_secs(timeout_minutes as u64 * 60);
        let warning_time = timeout.saturating_sub(Duration::from_secs(120));

        // Wait until warning time
        tokio::time::sleep(warning_time).await;

        tracing::info!(
            session_id = %session_id,
            user_id = %user_id,
            "Session timeout warning: 2 minutes remaining"
        );

        // TODO: Send warning to client via tunnel message

        // Wait remaining 2 minutes
        tokio::time::sleep(Duration::from_secs(120)).await;

        tracing::info!(
            session_id = %session_id,
            user_id = %user_id,
            "Session timeout reached, disconnecting"
        );

        let _ = shutdown_tx.send(());
    });
}
```

### Phase 6: Add New Error Type

**File:** `src/error.rs`

```rust
#[derive(Debug, Error)]
pub enum RelayError {
    // ... existing variants ...

    #[error("Limit exceeded: {0}")]
    LimitExceeded(String),
}

impl From<RelayError> for tonic::Status {
    fn from(e: RelayError) -> Self {
        match e {
            // ... existing matches ...
            RelayError::LimitExceeded(msg) => {
                Status::resource_exhausted(msg)
            }
        }
    }
}
```

## Acceptance Criteria

### Functional
- [ ] Free tier users cannot connect more than 1 daemon (host)
- [ ] Free tier users cannot create more than 2 concurrent sessions
- [ ] Free tier client sessions auto-disconnect after 15 minutes with 2-min warning
- [ ] Pro tier users can connect up to 5 daemons
- [ ] Pro/Team/Enterprise have no session limits or timeouts (-1)
- [ ] Daemon reconnection (same fingerprint) doesn't count as new host
- [ ] **Daemons can stay connected indefinitely** (no timeout on daemon connections)
- [ ] Clear error messages with upgrade prompts when limits exceeded

### Non-Functional
- [ ] Limit checks add < 1ms latency (registry queries are O(n) but n is small)
- [ ] Plan downgrades don't force-disconnect existing sessions (grandfather until natural end)
- [ ] **Backward compatibility**: Missing JWT claims default to free tier limits (via `#[serde(default)]`)
- [ ] **Race condition safe**: Atomic check-and-insert prevents concurrent connection bypass

## Edge Cases

### Daemon vs Client Session Timeout
- **Daemons** (hosts): No timeout - stay connected indefinitely
- **Client sessions** (tunnels/interactive): Subject to `sessionTimeoutMinutes`
- Rationale: Daemons need persistent availability; sessions are user-initiated and bounded

### Plan Upgrade Mid-Session
- New limits take effect on next JWT refresh (typically on reconnect or token expiry)
- Existing sessions continue with old timeout (grandfathered)

### Plan Downgrade Mid-Session
- Existing hosts/sessions continue until natural termination
- New connections/sessions blocked if over new limit
- No force-disconnection of existing resources

### Network Reconnection
- Same fingerprint reconnecting = same host (count stays at 1, no limit check)
- Different fingerprint = new host (blocks if at limit)

### Missing JWT Claims (Backward Compatibility)
- If `limits` claim is missing, default to free tier limits via `#[serde(default)]`
- Log warning for monitoring

### Race Condition (Concurrent Connections)
- Use atomic `try_insert_with_limit()` instead of separate count + insert
- Prevents two connections racing to exceed the limit

## Files to Modify

| File | Change |
|------|--------|
| `src/auth.rs` | Add `PlanLimits` struct with `#[serde(default)]`, extend `Claims` |
| `src/daemon/registry.rs` | Add `try_insert_with_limit()`, `count_by_user()` methods |
| `src/daemon/connection.rs` | Add host limit check in `accept_daemon()` |
| `src/session/registry.rs` | Add `try_insert_with_limit()`, `count_active_by_user()` methods |
| `src/session/mod.rs` | Add session limit check, spawn timeout task |
| `src/error.rs` | Add `LimitExceeded` variant |
| Dashboard API | Include limits in `/api/auth/user-claims` response |
| Auth0 Dashboard | Update Post-Login Action to inject limits |

## Testing Strategy

1. **Unit tests**: Registry atomic insert methods
2. **Integration tests**:
   - Connect 2 daemons as free user, verify second rejected
   - Create 3 sessions as free user, verify third rejected
   - Start session as free user, verify disconnects after 15 min
   - Verify daemon stays connected beyond 15 min (no daemon timeout)
   - Verify Pro user sessions have no timeout
3. **Race condition test**: Concurrent connection attempts at limit boundary
4. **Backward compatibility test**: JWT without limits claim defaults to free tier

## Estimated LOC

~80 lines of Rust (down from ~250 in original plan):
- `PlanLimits` struct with defaults: ~30 LOC
- Registry methods: ~20 LOC
- Limit checks in accept_daemon/handle_session: ~15 LOC
- Timeout spawned task: ~15 LOC
- Error variant: ~5 LOC

## References

### Internal
- `src/daemon/connection.rs` - Daemon acceptance flow
- `src/session/mod.rs` - Session handling
- `src/auth.rs` - Current Claims struct

### External
- [Auth0 Custom Claims](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-token-claims)
- [gRPC Status Codes](https://grpc.github.io/grpc/core/md_doc_statuscodes.html) - RESOURCE_EXHAUSTED for quota errors
