# Product Requirements Document: omnivault-onepassword

## Overview

**omnivault-onepassword** is a Go library that provides an OmniVault provider for 1Password, enabling applications to seamlessly access secrets stored in 1Password vaults using the unified OmniVault interface.

## Problem Statement

Developers using 1Password for secret management need a consistent, Go-native way to access their secrets programmatically. While 1Password provides an official Go SDK, it has its own API that differs from other secret management solutions. This creates friction when:

- Migrating between secret management providers
- Building applications that need to support multiple secret backends
- Standardizing secret access patterns across teams

## Solution

Provide an OmniVault-compatible provider that wraps the official 1Password Go SDK, allowing developers to:

- Access 1Password secrets using the familiar `vault.Vault` interface
- Use 1Password alongside other providers (AWS Secrets Manager, OS Keychain, etc.)
- Switch between providers without changing application code
- Leverage 1Password's enterprise features through a simple API

## Target Users

1. **Go Developers** building applications that need secure secret management
2. **DevOps Engineers** managing secrets across multiple environments
3. **Platform Teams** standardizing secret access patterns
4. **1Password Business/Teams Users** with service account access

## User Stories

### US-1: Basic Secret Retrieval

> As a developer, I want to retrieve a secret from 1Password using a simple path, so that I can use it in my application without learning the 1Password-specific API.

**Acceptance Criteria:**

- Can retrieve a secret using `provider.Get(ctx, "vault/item/field")`
- Returns a `vault.Secret` with the field value
- Returns `vault.ErrSecretNotFound` if the secret doesn't exist

### US-2: Multi-Field Secret Access

> As a developer, I want to retrieve all fields from a 1Password item, so that I can access credentials with multiple components (username, password, URL).

**Acceptance Criteria:**

- Can retrieve an item with multiple fields
- Fields are accessible via `secret.Fields["fieldname"]`
- Supports common field types (text, concealed, URL, TOTP)

### US-3: Secret Creation

> As a developer, I want to create new secrets in 1Password, so that I can programmatically manage credentials.

**Acceptance Criteria:**

- Can create a new item using `provider.Set(ctx, path, secret)`
- Supports specifying item category (Login, APICredentials, etc.)
- Supports multi-field secrets

### US-4: Secret Deletion

> As a developer, I want to delete secrets from 1Password, so that I can clean up unused credentials.

**Acceptance Criteria:**

- Can delete an item using `provider.Delete(ctx, path)`
- Deleting a non-existent item returns nil (idempotent)

### US-5: Secret Listing

> As a developer, I want to list secrets in a vault, so that I can discover available credentials.

**Acceptance Criteria:**

- Can list items using `provider.List(ctx, prefix)`
- Returns item paths matching the prefix
- Supports listing across multiple vaults

### US-6: OmniVault Integration

> As a developer, I want to use 1Password with the OmniVault resolver, so that I can use URI-based secret references.

**Acceptance Criteria:**

- Can register provider with resolver: `resolver.Register("op", provider)`
- Can resolve secrets: `resolver.Resolve(ctx, "op://vault/item/field")`

### US-7: Batch Secret Resolution

> As a developer, I want to resolve multiple secrets in a single call, so that I can reduce latency when loading configuration.

**Acceptance Criteria:**

- Implements `BatchVault` interface
- `GetBatch()` uses 1Password's `ResolveAll()` API
- Returns partial results if some secrets fail

## Functional Requirements

### FR-1: Authentication

- Support 1Password Service Account tokens
- Token can be provided via:
  - Direct configuration
  - Environment variable (`OP_SERVICE_ACCOUNT_TOKEN`)
- Clear error messages for authentication failures

### FR-2: Path Format

Support flexible path formats:

| Format | Example | Behavior |
|--------|---------|----------|
| `vault/item/field` | `Private/API Keys/token` | Resolve specific field |
| `vault/item` | `Private/Database Creds` | Return all fields |
| Native reference | `op://Private/API Keys/token` | Pass through to SDK |

### FR-3: Item Categories

Support creating items with appropriate categories:

- `Login` - Username/password combinations
- `APICredentials` - API keys and tokens
- `SecureNote` - Text-only secrets
- `Database` - Database credentials
- `Server` - Server/SSH credentials

### FR-4: Field Types

Map 1Password field types to vault.Secret:

| 1Password Type | vault.Secret Field |
|----------------|-------------------|
| `Text` | `Fields[name]` |
| `Concealed` | `Fields[name]` or `Value` |
| `URL` | `Fields[name]` |
| `TOTP` | `Fields[name]` (computed code) |
| `Email` | `Fields[name]` |
| `Phone` | `Fields[name]` |

### FR-5: Metadata

Populate `vault.Secret.Metadata` with:

- `Provider`: "onepassword"
- `Path`: Original path
- `CreatedAt`: Item creation time
- `ModifiedAt`: Item update time
- `Version`: Item version number
- `Extra["vaultId"]`: 1Password vault ID
- `Extra["itemId"]`: 1Password item ID
- `Extra["category"]`: Item category

### FR-6: Error Handling

Map 1Password errors to OmniVault errors:

| 1Password Error | OmniVault Error |
|-----------------|-----------------|
| Item not found | `vault.ErrSecretNotFound` |
| Vault not found | `vault.ErrSecretNotFound` |
| Access denied | `vault.ErrAccessDenied` |
| Rate limited | `vault.ErrRateLimited` (new) |
| Invalid token | `vault.ErrAccessDenied` |

## Non-Functional Requirements

### NFR-1: Performance

- Single secret retrieval: < 500ms (network dependent)
- Batch retrieval: < 1s for up to 10 secrets
- List operation: < 2s for vaults with < 1000 items

### NFR-2: Reliability

- Graceful handling of network failures
- Clear error messages with actionable guidance
- No panics on invalid input

### NFR-3: Security

- Never log secret values
- Clear sensitive data from memory when possible
- Support for 1Password's encryption at rest

### NFR-4: Compatibility

- Go 1.22+ (match omnivault core)
- Works on macOS, Linux, Windows
- Compatible with 1Password Business/Teams accounts

### NFR-5: Observability

- Structured logging support (optional)
- Context propagation for tracing
- Metrics hooks (optional)

## Out of Scope (v1.0)

- User authentication (service accounts only)
- 1Password Connect server support
- Vault creation/management
- User/group management
- Secret rotation automation
- File attachment content retrieval
- Passkey support

## Success Metrics

1. **Adoption**: Downloads/imports from pkg.go.dev
2. **Reliability**: < 1% error rate in production usage
3. **Performance**: P95 latency < 500ms for Get operations
4. **Quality**: > 80% test coverage

## Dependencies

- `github.com/agentplexus/omnivault` - Core vault interface
- `github.com/1password/onepassword-sdk-go` - Official 1Password SDK

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| 1Password SDK breaking changes | High | Pin SDK version, monitor releases |
| Service account rate limits | Medium | Implement caching layer (optional) |
| SDK requires Go 1.24+ | Medium | Document requirement, provide guidance |
| WASM runtime compatibility | Low | Test on all target platforms |

## Timeline

See [ROADMAP.md](./ROADMAP.md) for detailed implementation timeline.

## Appendix

### A. Example Usage

```go
package main

import (
    "context"
    "fmt"
    "os"

    "github.com/agentplexus/omnivault"
    op "github.com/agentplexus/omnivault-onepassword"
)

func main() {
    // Create 1Password provider
    provider, err := op.New(op.Config{
        ServiceAccountToken: os.Getenv("OP_SERVICE_ACCOUNT_TOKEN"),
    })
    if err != nil {
        panic(err)
    }
    defer provider.Close()

    // Use directly
    secret, err := provider.Get(context.Background(), "Private/API Keys/github-token")
    if err != nil {
        panic(err)
    }
    fmt.Println("Token:", secret.Value)

    // Or with OmniVault resolver
    resolver := omnivault.NewResolver()
    resolver.Register("op", provider)

    value, err := resolver.Resolve(context.Background(), "op://Private/API Keys/github-token")
    if err != nil {
        panic(err)
    }
    fmt.Println("Token:", value)
}
```

### B. Competitive Analysis

| Feature | omnivault-onepassword | 1Password CLI | 1Password Connect |
|---------|----------------------|---------------|-------------------|
| Go native | Yes | No (exec) | Yes |
| Service accounts | Yes | Yes | No |
| Unified interface | Yes | No | No |
| Self-hosted | No | No | Yes |
| Multi-provider | Yes | No | No |
