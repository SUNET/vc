# Verifier to Verifier-Proxy Migration Plan

> **⚠️ SUPERSEDED**: This document has been superseded by [VERIFIER_MERGE_PLAN.md](./VERIFIER_MERGE_PLAN.md).
>
> The migration has been **completed** as of December 2025. The verifier and verifier-proxy services have been successfully merged into a single unified verifier component.
>
> This document is preserved for historical reference only.

---

**Date:** November 26, 2025  
**Status:** ~~Planning Document~~ **SUPERSEDED**  
**Author:** Generated Analysis

## Executive Summary

This document provides a comprehensive analysis of the differences between the `verifier` and `verifier-proxy` services and outlines a migration plan to consolidate functionality into `verifier-proxy`, eliminating the `verifier` service.

**Key Decision:** The two services serve fundamentally different architectural purposes but share core verification logic. The migration will preserve verifier-proxy's OIDC Provider capabilities while deprecating the simpler direct-verification service.

## Table of Contents

1. [Service Comparison](#service-comparison)
2. [Architectural Differences](#architectural-differences)
3. [Feature Matrix](#feature-matrix)
4. [Migration Strategy](#migration-strategy)
5. [Implementation Plan](#implementation-plan)
6. [Risk Assessment](#risk-assessment)
7. [Testing Strategy](#testing-strategy)

---

## Service Comparison

### Verifier (Legacy Service)

**Purpose:** Direct OpenID4VP credential verification service

**Location:**
- Command: `cmd/verifier/`
- Implementation: `internal/verifier/`
- Configuration: `cfg.Verifier`

**Key Characteristics:**
- Simple, direct wallet-to-verifier communication
- Browser-based UI with Server-Sent Events (SSE)
- Notification service for real-time updates
- Used by UI service for credential presentation demos
- OAuth2 server metadata support
- Simpler session management
- Direct credential verification and caching

**API Endpoints:**
```
GET  /health                      # Health check
GET  /ui/verification             # Verification UI page
POST /verification/initiate       # Start verification
GET  /verification/notify         # SSE notifications
POST /verification/direct_post    # Wallet response
GET  /token                       # OAuth2 token endpoint
```

**Dependencies:**
- MongoDB (authorization contexts)
- Notification service (broadcast channels)
- OpenID4VP client
- Trust service

**Use Case:** Direct credential verification for demos, testing, and simple integrations

---

### Verifier-Proxy (Modern Service)

**Purpose:** OIDC Provider that bridges traditional OIDC Relying Parties with OpenID4VP wallets

**Location:**
- Command: `cmd/verifier-proxy/`
- Implementation: `internal/verifier_proxy/`
- Configuration: `cfg.VerifierProxy`

**Key Characteristics:**
- Full OIDC Provider (OpenID Connect Provider)
- Dynamic Client Registration (DCR)
- PKCE support (RFC 7636)
- Sophisticated session management
- Authorization code flow
- ID token and access token issuance
- Configurable presentation templates
- Claims mapping from credentials to OIDC claims
- W3C Digital Credentials API support
- Credential display/debugging features

**API Endpoints:**
```
# OIDC Discovery
GET  /.well-known/openid-configuration
GET  /.well-known/oauth-authorization-server

# OIDC Core
GET  /authorize                          # Authorization endpoint
POST /token                              # Token endpoint
GET  /userinfo                           # UserInfo endpoint
POST /revoke                             # Token revocation

# Client Management
POST /register                           # Dynamic client registration
GET  /register/:client_id                # Get client
PUT  /register/:client_id                # Update client
DELETE /register/:client_id              # Delete client

# OpenID4VP Integration
GET  /authorization/jar/:id              # JWT Authorization Request
POST /authorization/direct_post          # Wallet presentation response

# W3C Digital Credentials API
GET  /verification/session-preference    # User display preference
GET  /verification/display/:session_id   # Credential display page
POST /verification/confirm/:session_id   # User confirmation

# Utilities
GET  /qr/:session_id                     # QR code for wallet
GET  /poll/:session_id                   # Session status polling
GET  /health                             # Health check
```

**Dependencies:**
- MongoDB (sessions, clients, authorization codes)
- OpenID4VP client
- OIDC signing keys (RSA/EC)
- Claims extractor
- Trust service

**Use Cases:**
- Keycloak integration (OIDC RP → wallet authentication)
- Auth0, Okta, Azure AD integration
- Any OIDC-compliant relying party
- Production identity federation
- Wallet-based SSO

---

## Architectural Differences

### 1. Protocol Layer

| Aspect | Verifier | Verifier-Proxy |
|--------|----------|----------------|
| **Primary Protocol** | OpenID4VP only | OIDC Provider + OpenID4VP Verifier |
| **Client Interface** | Direct browser/wallet | OIDC Relying Parties |
| **Token Types** | Simple OAuth2 tokens | ID tokens, access tokens, refresh tokens |
| **Authentication Flow** | Direct presentation | Authorization Code Flow with PKCE |
| **Session Model** | Simple context storage | Full OIDC session with lifecycle |

### 2. Data Models

**Verifier Database Collections:**
```
verifier_authorization_context
  - id (string)
  - scope (string)
  - credentials (array)
  - status (string)
  - created_at (timestamp)
  - updated_at (timestamp)
```

**Verifier-Proxy Database Collections:**
```
sessions
  - id (string)
  - client_id (string)
  - oidc_request (object)
    - redirect_uri
    - scope
    - state
    - nonce
    - code_challenge
    - code_challenge_method
    - show_credential_details (bool)
  - openid4vp (object)
    - presentation_definition
    - request_object_id
    - request_object_nonce
    - verified_presentation (object)
  - tokens (object)
    - authorization_code
    - access_token
    - id_token
    - refresh_token
  - status (string)
  - expires_at (timestamp)
  - created_at (timestamp)
  - updated_at (timestamp)

clients
  - id (string)
  - client_id (string)
  - client_secret_hash (string)
  - redirect_uris (array)
  - grant_types (array)
  - response_types (array)
  - scope (string)
  - token_endpoint_auth_method (string)
  - created_at (timestamp)
  - updated_at (timestamp)

authorization_codes (TTL index)
  - code (string)
  - session_id (string)
  - expires_at (timestamp)
```

### 3. Configuration Structure

**Verifier Config:**
```yaml
verifier:
  api_server:
    addr: :8080
  grpc_server:
    addr: :8090
  public_url: "http://verifier:8080"
  supported_wallets:
    "SUNET dev": "https://dev.wallet.sunet.se/cb"
  oauth_server:
    token_endpoint: "http://verifier:8080/token"
    metadata:
      path: /metadata/oauth2_metadata.json
      signing_key_path: "/pki/key.pem"
  issuer_metadata:
    path: /metadata/issuer_metadata.json
```

**Verifier-Proxy Config:**
```yaml
verifier_proxy:
  api_server:
    addr: :8080
    tls:
      enabled: false
  external_url: "http://verifier-proxy:8080"
  
  # OIDC Provider configuration
  oidc:
    issuer: "http://verifier-proxy:8080"
    signing_key_path: "/private_rsa.pem"
    signing_alg: "RS256"
    session_duration: 900
    authorization_code_duration: 300
    access_token_duration: 3600
    id_token_duration: 3600
    refresh_token_duration: 2592000
    subject_type: "pairwise"
    subject_salt: "production-secret"
  
  # OpenID4VP configuration
  openid4vp:
    presentation_timeout: 300
    supported_credentials:
      - vct: "urn:eudi:pid:1"
        scopes: ["pid"]
        claims:
          given_name: "$.credentialSubject.given_name"
          family_name: "$.credentialSubject.family_name"
    presentation_requests_dir: "/presentation_requests"
  
  # W3C Digital Credentials API
  digital_credentials:
    enabled: true
    preferred_formats: ["vc+sd-jwt", "mso_mdoc"]
    use_jar: true
    
  # Credential display (debugging)
  credential_display:
    enabled: true
    require_confirmation: false
    show_raw_credential: true
    show_claims: true
```

### 4. Service Dependencies

**Verifier Dependencies:**
```
main.go
  ├─> db.Service (MongoDB)
  ├─> notify.Service (SSE broadcasts)
  ├─> apiv1.Client
  │     ├─> openid4vp.Client
  │     ├─> TrustService
  │     └─> credentialCache (TTL)
  └─> httpserver.Service
        ├─> Gin router
        └─> Session store
```

**Verifier-Proxy Dependencies:**
```
main.go
  ├─> db.Service (MongoDB)
  ├─> apiv1.Client
  │     ├─> openid4vp.Client
  │     ├─> ClaimsExtractor
  │     ├─> TrustService
  │     ├─> ephemeralEncryptionKeyCache (TTL)
  │     ├─> requestObjectCache (TTL)
  │     └─> presentationTemplates (map)
  └─> httpserver.Service
        ├─> Gin router
        └─> Route groups (oidc, verification, registration)
```

---

## Feature Matrix

| Feature | Verifier | Verifier-Proxy | Notes |
|---------|----------|----------------|-------|
| **Core Verification** |
| OpenID4VP presentation request | ✅ | ✅ | Both use `pkg/openid4vp` |
| SD-JWT verification | ✅ | ✅ | Both use `pkg/sdjwt3` |
| Credential caching | ✅ | ✅ | Different TTL strategies |
| Trust framework validation | ✅ | ✅ | Shared `TrustService` |
| **OIDC Features** |
| Authorization endpoint | ❌ | ✅ | Full OAuth 2.0 flow |
| Token endpoint | ⚠️ Simple | ✅ Full | Verifier has basic OAuth2 |
| UserInfo endpoint | ❌ | ✅ | OIDC standard |
| Discovery endpoints | ❌ | ✅ | `.well-known` |
| Dynamic Client Registration | ❌ | ✅ | RFC 7591 |
| PKCE support | ❌ | ✅ | RFC 7636 |
| ID token issuance | ❌ | ✅ | With claims mapping |
| Refresh tokens | ❌ | ✅ | Long-lived sessions |
| **Session Management** |
| Session storage | ⚠️ Basic | ✅ Advanced | Context vs full session |
| Session expiration | ✅ | ✅ | Verifier-proxy more granular |
| State management | ✅ | ✅ | Both support state param |
| **Presentation Features** |
| Configurable templates | ❌ | ✅ | File-based templates |
| Claims mapping | ❌ | ✅ | JSONPath extraction |
| Multiple credential types | ⚠️ Via config | ✅ Per-template | |
| DCQL support | ✅ | ✅ | Both support DCQL queries |
| **User Interface** |
| Authorization page | ❌ | ✅ | Themed, configurable |
| SSE notifications | ✅ | ❌ | Verifier only |
| Polling mechanism | ❌ | ✅ | Verifier-proxy fallback |
| QR code display | ✅ | ✅ | Both support |
| Credential display | ❌ | ✅ | New debugging feature |
| **Advanced Features** |
| W3C Digital Credentials API | ❌ | ✅ | Browser API support |
| JAR (JWT Authorization Request) | ❌ | ✅ | Encrypted requests |
| Multiple response modes | ⚠️ Limited | ✅ Full | dc_api.jwt, direct_post.jwt |
| Subject identifiers | ❌ | ✅ | Pairwise/public |
| **Integration** |
| Keycloak/OIDC RP support | ❌ | ✅ | Primary use case |
| Direct wallet integration | ✅ | ✅ | Both support |
| UI service integration | ✅ | ⚠️ Possible | Currently uses verifier |
| gRPC API | ✅ | ❌ | Verifier only |

**Legend:**
- ✅ Fully supported
- ⚠️ Partially supported or basic implementation
- ❌ Not supported

---

## Migration Strategy

### Phase 1: Analysis & Planning (Week 1)

**Goals:**
- Complete dependency analysis
- Identify breaking changes
- Plan backward compatibility layer

**Tasks:**
1. ✅ Document all services that depend on `verifier`
   - UI service (`internal/ui/apiv1/verifier_client.go`)
   - Any external integrations
   
2. ✅ Catalog API endpoint differences
   - Map old endpoints to new equivalents
   - Identify endpoints without equivalents

3. ✅ Analyze configuration migration
   - Create config migration guide
   - Document new required fields

4. ✅ Database migration strategy
   - Plan data migration from `verifier_authorization_context`
   - Determine if dual-write period needed

### Phase 2: Foundation Work (Week 2-3)

**Goals:**
- Prepare verifier-proxy for backward compatibility
- Create migration tooling
- Update shared packages

**Tasks:**

#### 2.1 Add Backward Compatibility to Verifier-Proxy

Create compatibility layer for verifier's simple API:

```go
// internal/verifier_proxy/apiv1/handler_legacy_verifier.go
package apiv1

// LegacyVerificationRequest matches old verifier API
type LegacyVerificationRequest struct {
    Scope       string   `json:"scope"`
    Credentials []string `json:"credentials,omitempty"`
}

// LegacyVerificationResponse matches old verifier API
type LegacyVerificationResponse struct {
    ID          string `json:"id"`
    RedirectURI string `json:"redirect_uri"`
    Status      string `json:"status"`
}

// LegacyInitiateVerification provides backward-compatible endpoint
func (c *Client) LegacyInitiateVerification(ctx context.Context, req *LegacyVerificationRequest) (*LegacyVerificationResponse, error) {
    // Map to new authorization flow
    // Create synthetic OIDC client for legacy requests
    // Return compatible response
}
```

#### 2.2 Create SSE Compatibility Layer (Optional)

If SSE notifications are required:

```go
// internal/verifier_proxy/httpserver/endpoints_legacy_notify.go
package httpserver

// endpointLegacyNotify provides SSE compatibility
func (s *Service) endpointLegacyNotify(c *gin.Context) {
    // Implement SSE using session polling
    // Translate session status updates to SSE events
}
```

#### 2.3 UI Service Migration

Update UI service to use verifier-proxy:

**Option A: Use OIDC Flow (Recommended)**
```go
// internal/ui/apiv1/verifier_proxy_client.go
type VerifierProxyClient struct {
    *VCBaseClient
}

func NewVerifierProxyClient(cfg *model.Cfg, tracer *trace.Tracer, logger *logger.Log) *VerifierProxyClient {
    return &VerifierProxyClient{
        VCBaseClient: NewClient("VerifierProxy", cfg.UI.Services.VerifierProxy.BaseURL, tracer, logger),
    }
}

// Use standard OIDC flow instead of direct verification
```

**Option B: Use Legacy Compatibility Endpoints**
```go
// Keep existing VerifierClient but point to verifier-proxy
// Use compatibility endpoints
```

#### 2.4 Configuration Migration Tool

```bash
#!/bin/bash
# scripts/migrate-verifier-config.sh

# Migrate config.yaml from verifier to verifier_proxy format
sed 's/^verifier:/verifier_proxy:/' config.yaml > config.new.yaml

# Add required new fields with defaults
cat >> config.new.yaml <<EOF
  oidc:
    issuer: "${EXTERNAL_URL}"
    signing_key_path: "${SIGNING_KEY_PATH}"
    signing_alg: "RS256"
    session_duration: 900
    authorization_code_duration: 300
EOF
```

### Phase 3: Dual-Run Period (Week 4-6)

**Goals:**
- Run both services simultaneously
- Migrate traffic gradually
- Validate equivalent behavior

**Tasks:**

#### 3.1 Deploy Both Services

Update `docker-compose.yaml`:
```yaml
services:
  # Keep old verifier
  verifier:
    container_name: "vc_dev_verifier"
    image: docker.sunet.se/dc4eu/verifier:latest
    # ... existing config

  # New verifier-proxy
  verifier-proxy:
    container_name: "vc_dev_verifier_proxy"
    image: docker.sunet.se/dc4eu/verifier-proxy:latest
    # ... existing config
```

#### 3.2 Route Splitting

Use reverse proxy to gradually shift traffic:
```nginx
# nginx.conf
upstream verifier_backend {
    server verifier:8080 weight=80;
    server verifier-proxy:8080 weight=20;
}

location / {
    proxy_pass http://verifier_backend;
}
```

#### 3.3 Monitoring & Validation

- Compare response times
- Validate equivalent credential verification
- Monitor error rates
- Check session handling

### Phase 4: Migration & Cleanup (Week 7-8)

**Goals:**
- Complete migration to verifier-proxy
- Remove old verifier service
- Clean up codebase

**Tasks:**

#### 4.1 Update All References

```bash
# Find all references to old verifier
grep -r "cfg\.Verifier\." --include="*.go" .
grep -r "internal/verifier" --include="*.go" .
grep -r "cmd/verifier" --include="*.go" .
```

#### 4.2 Remove Old Code

```bash
# Remove verifier service
git rm -rf cmd/verifier/
git rm -rf internal/verifier/
git rm -rf docs/verifier/

# Update Makefile
sed -i '/build-verifier:/,+2d' Makefile
sed -i 's/verifier //' Makefile  # Remove from SERVICES list

# Update docker-compose.yaml
# Remove verifier service block

# Remove from UI dependencies
git rm internal/ui/apiv1/verifier_client.go
```

#### 4.3 Rename verifier-proxy to verifier (Optional)

If you want cleaner naming:

```bash
# Rename directories
git mv cmd/verifier-proxy cmd/verifier
git mv internal/verifier_proxy internal/verifier

# Update import paths
find . -name "*.go" -type f -exec sed -i 's|vc/internal/verifier_proxy|vc/internal/verifier|g' {} +

# Update config structure
# Change verifier_proxy: to verifier: in config.yaml
# Update pkg/model/config.go to rename VerifierProxy struct
```

#### 4.4 Update Documentation

- Update README.md
- Update architecture diagrams
- Update API documentation
- Create migration guide for external users

---

## Implementation Plan

### Detailed Task Breakdown

#### Task 1: Prepare Verifier-Proxy for Legacy Support

**Files to Create:**
- `internal/verifier_proxy/apiv1/handler_legacy_verifier.go`
- `internal/verifier_proxy/httpserver/endpoints_legacy.go`

**Implementation:**
```go
// handler_legacy_verifier.go
package apiv1

import (
    "context"
    "fmt"
    "vc/pkg/model"
    "vc/pkg/oauth2"
)

// Legacy API support for old verifier endpoints

type LegacyInitiateRequest struct {
    Scope string `json:"scope" binding:"required"`
}

type LegacyInitiateResponse struct {
    ID          string `json:"id"`
    RedirectURI string `json:"redirect_uri"`
    Status      string `json:"status"`
}

func (c *Client) LegacyInitiateVerification(ctx context.Context, req *LegacyInitiateRequest) (*LegacyInitiateResponse, error) {
    // Create a synthetic OIDC client for legacy requests
    syntheticClient := &model.Client{
        ClientID:     "legacy-verifier-client",
        RedirectURIs: []string{fmt.Sprintf("%s/verification/callback", c.cfg.VerifierProxy.ExternalURL)},
        GrantTypes:   []string{"authorization_code"},
        Scope:        req.Scope,
    }

    // Create authorization request
    authReq := &AuthorizeRequest{
        ClientID:     syntheticClient.ClientID,
        RedirectURI:  syntheticClient.RedirectURIs[0],
        Scope:        req.Scope,
        State:        oauth2.GenerateState(),
        ResponseType: "code",
        Nonce:        oauth2.GenerateNonce(),
    }

    // Process authorization (creates session)
    authResp, err := c.ProcessAuthorize(ctx, authReq)
    if err != nil {
        return nil, err
    }

    return &LegacyInitiateResponse{
        ID:          authResp.SessionID,
        RedirectURI: authResp.RequestObjectURI,
        Status:      "initiated",
    }, nil
}
```

#### Task 2: Update UI Service

**Files to Modify:**
- `internal/ui/apiv1/verifier_proxy_client.go` (new)
- `internal/ui/httpserver/endpoints_*.go` (update to use new client)
- `config.yaml` (add verifier_proxy section to UI)

**Implementation:**
```go
// verifier_proxy_client.go
package apiv1

import (
    "vc/pkg/logger"
    "vc/pkg/model"
    "vc/pkg/trace"
)

type VerifierProxyClient struct {
    *VCBaseClient
}

func NewVerifierProxyClient(cfg *model.Cfg, tracer *trace.Tracer, logger *logger.Log) *VerifierProxyClient {
    return &VerifierProxyClient{
        VCBaseClient: NewClient("VerifierProxy", cfg.UI.Services.VerifierProxy.BaseURL, tracer, logger),
    }
}

func (c *VerifierProxyClient) InitiateVerification(scope string) (map[string]interface{}, error) {
    // Use legacy compatibility endpoint or full OIDC flow
    reply, err := c.DoPostJSON("/verification/legacy/initiate", map[string]string{
        "scope": scope,
    })
    if err != nil {
        return nil, err
    }
    return reply, nil
}
```

#### Task 3: Database Migration

**Create migration script:**
```javascript
// scripts/migrate-verifier-db.js
// MongoDB migration script

// Connect to database
const db = db.getSiblingDB('verifier_proxy');

// Migrate authorization contexts to sessions
db.verifier_authorization_context.find().forEach(function(ctx) {
    const session = {
        id: ctx.id,
        client_id: "migrated-legacy-client",
        oidc_request: {
            scope: ctx.scope,
            state: ctx.id,
            redirect_uri: "http://localhost/callback"
        },
        openid4vp: {
            verified_presentation: ctx.credentials
        },
        status: ctx.status,
        created_at: ctx.created_at,
        updated_at: ctx.updated_at,
        expires_at: new Date(ctx.updated_at.getTime() + 900000) // 15 minutes
    };
    
    db.sessions.insertOne(session);
});

print("Migration complete");
print("Migrated contexts:", db.verifier_authorization_context.count());
print("New sessions:", db.sessions.count());
```

#### Task 4: Update Build and Deployment

**Makefile changes:**
```makefile
# Remove old verifier target
# build-verifier:
# 	$(info Building verifier)
# 	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o ./bin/$(NAME)_verifier ${LDFLAGS} ./cmd/verifier/main.go

# Update SERVICES list
SERVICES := verifier-proxy registry persistent mockas apigw issuer ui wallet

# Or rename verifier-proxy to verifier
build-verifier:
	$(info Building verifier)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o ./bin/$(NAME)_verifier ${LDFLAGS} ./cmd/verifier-proxy/main.go
```

**Docker Compose changes:**
```yaml
# Remove old verifier service
# Update UI dependencies
ui:
  depends_on:
    - apigw
    - mockas
    - verifier-proxy  # Changed from verifier
```

---

## Risk Assessment

### High Risk Areas

#### 1. UI Service Dependency
**Risk:** UI service currently depends on verifier's SSE notifications  
**Impact:** High - UI functionality breaks  
**Mitigation:**
- Implement SSE compatibility layer in verifier-proxy
- Or migrate UI to use polling mechanism
- Test thoroughly before migration

#### 2. External Integrations
**Risk:** Unknown external services may depend on verifier API  
**Impact:** High - External breakage  
**Mitigation:**
- Maintain legacy compatibility endpoints
- Version API with deprecation warnings
- Communicate changes via changelog

#### 3. Database Schema Changes
**Risk:** Session data structure incompatibility  
**Impact:** Medium - Data loss risk  
**Mitigation:**
- Create comprehensive migration script
- Test migration on staging data
- Implement rollback capability

### Medium Risk Areas

#### 1. Configuration Complexity
**Risk:** More complex configuration in verifier-proxy  
**Impact:** Medium - Deployment issues  
**Mitigation:**
- Provide configuration migration tool
- Document all new required fields
- Provide example configs

#### 2. Performance Differences
**Risk:** Different caching/session strategies may affect performance  
**Impact:** Medium - User experience  
**Mitigation:**
- Load test both services
- Monitor metrics during migration
- Tune TTL values appropriately

### Low Risk Areas

#### 1. Code Duplication
**Risk:** Shared packages already used by both  
**Impact:** Low - Minimal refactoring needed  
**Mitigation:**
- Both use `pkg/openid4vp`
- Both use `pkg/sdjwt3`
- Minimal package changes needed

---

## Testing Strategy

### Unit Tests

**Existing Coverage:**
- Verifier: Basic coverage
- Verifier-Proxy: ~26.9% (apiv1), needs improvement

**Plan:**
1. Ensure legacy compatibility endpoints have tests
2. Add integration tests for UI service migration
3. Test configuration migration script

### Integration Tests

**Test Scenarios:**

1. **Legacy API Compatibility**
```go
func TestLegacyVerificationFlow(t *testing.T) {
    // Test old verifier API pattern
    // 1. POST /verification/initiate
    // 2. Wallet presents credential
    // 3. POST /verification/direct_post
    // 4. Verify results match old behavior
}
```

2. **UI Service Integration**
```go
func TestUIServiceVerification(t *testing.T) {
    // Test UI service can verify credentials
    // Using either legacy or OIDC flow
}
```

3. **OIDC RP Integration**
```go
func TestKeycloakIntegration(t *testing.T) {
    // Test full OIDC flow
    // Verify verifier-proxy works as OP
}
```

### Migration Testing

**Test Plan:**

1. **Pre-Migration Tests**
   - Capture baseline metrics from verifier
   - Document all API behaviors
   - Record session lifecycle patterns

2. **Dual-Run Testing**
   - Run both services with same requests
   - Compare responses for equivalence
   - Validate session data consistency

3. **Post-Migration Validation**
   - Verify all use cases work
   - Check performance metrics
   - Validate data migration

### Load Testing

```bash
# Test verifier-proxy under verifier's typical load
ab -n 10000 -c 100 http://verifier-proxy:8080/authorize?...
ab -n 10000 -c 100 http://verifier-proxy:8080/token
```

---

## Migration Checklist

### Pre-Migration

- [ ] Complete dependency analysis
- [ ] Document all verifier API consumers
- [ ] Create configuration migration guide
- [ ] Prepare database migration script
- [ ] Implement legacy compatibility layer
- [ ] Update UI service code
- [ ] Write migration documentation
- [ ] Create rollback plan

### Migration Execution

- [ ] Deploy verifier-proxy with legacy support
- [ ] Run dual services (verifier + verifier-proxy)
- [ ] Migrate UI service to use verifier-proxy
- [ ] Route 10% traffic to verifier-proxy
- [ ] Route 50% traffic to verifier-proxy
- [ ] Route 100% traffic to verifier-proxy
- [ ] Monitor for 48 hours
- [ ] Migrate database (if needed)

### Post-Migration

- [ ] Remove old verifier service
- [ ] Clean up code (remove internal/verifier/)
- [ ] Update Makefile
- [ ] Update docker-compose.yaml
- [ ] Update documentation
- [ ] Announce deprecation
- [ ] Remove legacy compatibility (future)

---

## Timeline

| Phase | Duration | Key Deliverables |
|-------|----------|------------------|
| Phase 1: Planning | 1 week | This document, dependency analysis |
| Phase 2: Foundation | 2 weeks | Legacy support, UI migration, tooling |
| Phase 3: Dual-Run | 3 weeks | Both services running, gradual migration |
| Phase 4: Cleanup | 2 weeks | Remove old code, documentation |
| **Total** | **8 weeks** | Verifier deprecated, verifier-proxy as sole service |

---

## Decision Log

### Decision 1: Keep Separate Services vs Merge

**Decision:** Merge into verifier-proxy as the sole verification service

**Rationale:**
- Verifier-proxy is more feature-complete
- OIDC Provider capabilities are superset of verifier
- Reduces maintenance burden
- Clearer architecture (single service for verification)

**Alternatives Considered:**
- Keep both services (rejected: duplication)
- Merge verifier-proxy into verifier (rejected: would lose OIDC features)

### Decision 2: Legacy Compatibility Layer

**Decision:** Implement compatibility endpoints in verifier-proxy

**Rationale:**
- Smooth migration path
- No breaking changes for UI service initially
- Can be deprecated later

**Alternatives Considered:**
- Force immediate API change (rejected: too risky)
- Maintain separate legacy service (rejected: defeats purpose)

### Decision 3: Naming

**Decision:** Keep name "verifier-proxy" during migration, consider rename later

**Rationale:**
- Less confusing during transition
- Can rename after migration complete
- Clearer in documentation

**Alternatives Considered:**
- Immediate rename to "verifier" (rejected: confusing during migration)

---

## Appendix A: API Mapping

### Verifier → Verifier-Proxy Endpoint Mapping

| Old Verifier Endpoint | New Verifier-Proxy Endpoint | Notes |
|----------------------|----------------------------|-------|
| `GET /health` | `GET /health` | Identical |
| `POST /verification/initiate` | `GET /authorize` (with legacy wrapper) | OIDC flow |
| `GET /verification/notify` | `GET /poll/:session_id` | SSE → Polling |
| `POST /verification/direct_post` | `POST /authorization/direct_post` | Same path |
| `GET /token` | `POST /token` | Now supports full OIDC |
| `GET /ui/verification` | N/A | UI-specific, not migrated |

### Configuration Mapping

| Old Config Field | New Config Field | Notes |
|-----------------|------------------|-------|
| `verifier.api_server` | `verifier_proxy.api_server` | Same structure |
| `verifier.public_url` | `verifier_proxy.external_url` | Renamed |
| `verifier.oauth_server.token_endpoint` | `verifier_proxy.oidc.issuer` + `/token` | Auto-generated |
| N/A | `verifier_proxy.oidc.*` | New OIDC config |
| N/A | `verifier_proxy.openid4vp.*` | New OpenID4VP config |

---

## Appendix B: Code Examples

### Example: Legacy Compatibility Endpoint

```go
// internal/verifier_proxy/httpserver/endpoints_legacy.go
package httpserver

import (
    "net/http"
    "vc/internal/verifier_proxy/apiv1"
    "github.com/gin-gonic/gin"
)

// Legacy verifier endpoints for backward compatibility

func (s *Service) endpointLegacyInitiate(c *gin.Context) {
    ctx, span := s.tracer.Start(c.Request.Context(), "httpserver:legacy:initiate")
    defer span.End()

    var req apiv1.LegacyInitiateRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    resp, err := s.apiv1.LegacyInitiateVerification(ctx, &req)
    if err != nil {
        s.log.Error(err, "legacy initiate failed")
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, resp)
}

func (s *Service) endpointLegacyNotify(c *gin.Context) {
    // SSE implementation using session polling
    sessionID := c.Param("session_id")
    
    c.Header("Content-Type", "text/event-stream")
    c.Header("Cache-Control", "no-cache")
    c.Header("Connection", "keep-alive")

    // Poll session status and send SSE events
    // Implementation similar to polling but with SSE format
}
```

### Example: Configuration Migration

```yaml
# Old config.yaml (verifier)
verifier:
  api_server:
    addr: :8080
  public_url: "http://verifier:8080"
  oauth_server:
    token_endpoint: "http://verifier:8080/token"

# New config.yaml (verifier-proxy)
verifier_proxy:
  api_server:
    addr: :8080
  external_url: "http://verifier:8080"
  oidc:
    issuer: "http://verifier:8080"
    signing_key_path: "/pki/key.pem"
    signing_alg: "RS256"
    session_duration: 900
    authorization_code_duration: 300
    access_token_duration: 3600
    id_token_duration: 3600
    subject_type: "pairwise"
  openid4vp:
    presentation_timeout: 300
```

---

## Conclusion

The migration from `verifier` to `verifier-proxy` consolidates functionality into a more capable, production-ready service. The phased approach ensures minimal disruption while providing a clear upgrade path for all consumers.

**Key Success Factors:**
1. Comprehensive legacy compatibility layer
2. Thorough testing at each phase
3. Clear communication with stakeholders
4. Gradual traffic migration with monitoring
5. Documented rollback procedures

**Next Steps:**
1. Review and approve this plan
2. Begin Phase 1 (dependency analysis)
3. Set up project tracking
4. Schedule regular migration reviews

---

**Document Version:** 1.0  
**Last Updated:** November 26, 2025  
**Status:** Ready for Review
