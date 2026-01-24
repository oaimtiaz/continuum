# Short Enrollment Codes (ABC-123 Format)

## Status: IMPLEMENTED

## Problem

Current enrollment tokens are 184 base64 characters - too long to easily share or type:
```
AQAA-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-...
```

Users want a simple 6-character code like `ABC-123`.

## Solution: Single-Phase TOFU

Following the reviewers' recommendation, we implemented the **simplest possible solution**:

- Short codes use TOFU (Trust-On-First-Use)
- No manual fingerprint verification required
- Client trusts whatever server responds and saves the fingerprint
- Full tokens remain available for high-security scenarios

## Security Tradeoff

| Approach | First Connection | Convenience |
|----------|------------------|-------------|
| Full token (184 chars) | Verified (fingerprint embedded) | Low |
| Short code (6 chars) | TOFU | High |

**Why TOFU is acceptable:**
1. User explicitly chose convenience (short code)
2. Short codes expire quickly (5 min default)
3. Short codes are single-use
4. Full tokens remain for high-security needs
5. An attacker who can MITM could also intercept the short code

---

## Implementation Summary

### Files Modified

1. **continuum-proto/proto/enrollment.proto**
   - Added `short_code` field to `InitiateEnrollmentResponse`
   - Added `short_code` field to `RequestEnrollmentTokenResponse`

2. **continuum-daemon/src/auth/store.rs**
   - Added `short_code TEXT UNIQUE` column to `enrollment_tokens` table
   - Added `generate_short_code()` - generates 6-char Crockford Base32 codes
   - Added `normalize_short_code()` - normalizes user input
   - Added `is_short_code()` - detects short code format
   - Added `create_enrollment_token_with_short_code()` - stores token with code
   - Added `consume_short_code()` - validates and consumes codes

3. **continuum-daemon/src/services/enrollment.rs**
   - Updated `initiate_enrollment` to generate and return short codes
   - Updated `complete_enrollment` to accept short codes (detects format)
   - Updated `request_enrollment_token` to return short codes

4. **continuum-cli/src/tls/client.rs**
   - Added `TofuVerifier` - accepts any cert, captures fingerprint

5. **continuum-cli/src/commands/enroll.rs**
   - Added `is_short_code()` detection
   - Added `run_short_code_enrollment()` - TOFU flow
   - Updated `run_enrollment()` to route short codes to TOFU flow

---

## Usage

### Generating a short code (local)
```bash
$ continuum-daemon token generate
Enrollment code: HJK-NRT
Expires: 2024-01-23 10:05:00 (5 minutes)
```

### Generating a short code (remote via relay)
```bash
$ continuum generate-token --daemon SHA256:xxx
Short code: ABC-234
Full token: AQAA-xxxx-...
Expires at: 2024-01-23 10:05:00
```

### Enrolling with short code
```bash
$ continuum enroll HJK-NRT
Using short code enrollment (TOFU)...
Client fingerprint: SHA256:yyy
Server fingerprint stored: SHA256:xxx
Enrollment approved!
```

### Enrolling with full token (high security)
```bash
$ continuum enroll AQAA-xxxx-xxxx-...
Client fingerprint: SHA256:yyy
Server fingerprint stored: SHA256:xxx
Enrollment approved!
```

---

## Character Set

Uses Crockford Base32 for readability:
- Characters: `23456789ABCDEFGHJKMNPQRSTVWXYZ` (29 chars)
- Excludes: `0` (zero), `1` (one), `I`, `L`, `O`, `U`
- Case-insensitive input
- Format: `ABC-123` (dash for readability)

## Tests Added

- `test_generate_short_code_format` - validates format
- `test_generate_short_code_uniqueness` - ensures randomness
- `test_normalize_short_code` - validates normalization
- `test_is_short_code` - validates detection
- `test_create_and_consume_short_code` - full flow
- `test_short_code_expired` - expiration handling
- `test_short_code_case_insensitive` - case normalization
