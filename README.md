# omnivault-onepassword

[![Go Reference](https://pkg.go.dev/badge/github.com/agentplexus/omnivault-onepassword.svg)](https://pkg.go.dev/github.com/agentplexus/omnivault-onepassword)
[![CI](https://github.com/agentplexus/omnivault-onepassword/actions/workflows/ci.yaml/badge.svg)](https://github.com/agentplexus/omnivault-onepassword/actions/workflows/ci.yaml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

OmniVault provider for [1Password](https://1password.com/) using the official [1Password Go SDK](https://github.com/1Password/onepassword-sdk-go).

## Features

- Access 1Password secrets through the unified OmniVault interface
- Support for multi-field items (username, password, URL, etc.)
- Batch secret resolution for efficient bulk access
- TOTP code generation
- Full CRUD operations (create, read, update, delete)
- Flexible path formats including native `op://` references

## Requirements

- Go 1.22 or later (Go 1.24+ recommended for 1Password SDK)
- 1Password account with [Service Account](https://developer.1password.com/docs/service-accounts/get-started/) access
- Service account token with appropriate vault permissions

## Installation

```bash
go get github.com/agentplexus/omnivault-onepassword
```

## Quick Start

### 1. Create a Service Account

1. Go to [1Password Developer Tools](https://my.1password.com/developer-tools/infrastructure-secrets/serviceaccount/)
2. Create a new service account
3. Grant it access to the vaults you need

### 2. Set the Token

```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
```

### 3. Use the Provider

```go
package main

import (
    "context"
    "fmt"
    "log"

    op "github.com/agentplexus/omnivault-onepassword"
)

func main() {
    // Create provider (uses OP_SERVICE_ACCOUNT_TOKEN env var)
    provider, err := op.NewFromEnv()
    if err != nil {
        log.Fatal(err)
    }
    defer provider.Close()

    ctx := context.Background()

    // Get a specific field
    secret, err := provider.Get(ctx, "Private/API Keys/github-token")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Token:", secret.Value)

    // Get all fields from an item
    creds, err := provider.Get(ctx, "Private/Database Credentials")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Username:", creds.Fields["username"])
    fmt.Println("Password:", creds.Fields["password"])
}
```

## Path Formats

The provider supports multiple path formats:

| Format | Example | Description |
|--------|---------|-------------|
| `vault/item/field` | `Private/API Keys/token` | Full path to a specific field |
| `vault/item` | `Private/Database Creds` | All fields from an item |
| `item/field` | `API Keys/token` | With default vault configured |
| `item` | `API Keys` | Item in default vault |
| `op://vault/item/field` | `op://Private/API Keys/token` | Native 1Password reference |

## Configuration

```go
provider, err := op.New(op.Config{
    // Required: Service account token (or use OP_SERVICE_ACCOUNT_TOKEN env var)
    ServiceAccountToken: "ops_...",

    // Optional: Default vault for simplified paths
    DefaultVaultName: "Private",

    // Optional: Default category for new items
    DefaultCategory: op.CategoryLogin,

    // Optional: Integration identification
    IntegrationName:    "my-app",
    IntegrationVersion: "1.0.0",
})
```

## Usage with OmniVault Resolver

```go
import (
    "github.com/agentplexus/omnivault"
    op "github.com/agentplexus/omnivault-onepassword"
)

// Create provider
provider, _ := op.NewFromEnv()

// Register with resolver
resolver := omnivault.NewResolver()
resolver.Register("op", provider)

// Resolve secrets using URI syntax
token, _ := resolver.Resolve(ctx, "op://Private/API Keys/github-token")
```

## Operations

### Read Secrets

```go
// Get specific field
secret, err := provider.Get(ctx, "vault/item/field")
fmt.Println(secret.Value)

// Get all fields
secret, err := provider.Get(ctx, "vault/item")
for name, value := range secret.Fields {
    fmt.Printf("%s: %s\n", name, value)
}

// Check existence
exists, err := provider.Exists(ctx, "vault/item")
```

### Write Secrets

```go
// Create new item
err := provider.Set(ctx, "vault/new-item", &vault.Secret{
    Value: "secret-value",
    Fields: map[string]string{
        "username": "user@example.com",
        "password": "secure-password",
        "url":      "https://example.com",
    },
})

// Update specific field
err := provider.Set(ctx, "vault/item/password", &vault.Secret{
    Value: "new-password",
})
```

### Delete Secrets

```go
err := provider.Delete(ctx, "vault/item")
```

### List Secrets

```go
// List all items
items, err := provider.List(ctx, "")

// List items with prefix
items, err := provider.List(ctx, "Private/")
```

### Batch Operations

```go
// Get multiple secrets efficiently
results, err := provider.GetBatch(ctx, []string{
    "Private/API Keys/github",
    "Private/API Keys/aws",
    "Private/Database/prod",
})

for path, secret := range results {
    fmt.Printf("%s: %s\n", path, secret.Value)
}
```

## Field Type Inference

When creating items, field types are automatically inferred from names:

| Field Name Contains | 1Password Type |
|--------------------|----------------|
| password, secret, token, key | Concealed |
| url, website, endpoint | URL |
| phone, mobile, tel | Phone |
| (value starts with otpauth://) | TOTP |
| (other) | Text |

## Metadata

Retrieved secrets include rich metadata:

```go
secret, _ := provider.Get(ctx, "vault/item")

fmt.Println(secret.Metadata.Provider)   // "onepassword"
fmt.Println(secret.Metadata.Path)       // "vault/item"
fmt.Println(secret.Metadata.Version)    // "5"

// Extra metadata
fmt.Println(secret.Metadata.Extra["vaultId"])  // "abc123"
fmt.Println(secret.Metadata.Extra["itemId"])   // "def456"
fmt.Println(secret.Metadata.Extra["category"]) // "Login"

// Tags
for key, value := range secret.Metadata.Tags {
    fmt.Printf("Tag: %s=%s\n", key, value)
}
```

## Capabilities

```go
caps := provider.Capabilities()
// caps.Read       = true
// caps.Write      = true
// caps.Delete     = true
// caps.List       = true
// caps.MultiField = true
// caps.Batch      = true
// caps.Binary     = true
// caps.Versioning = false (SDK limitation)
// caps.Rotation   = false (SDK limitation)
```

## Error Handling

```go
secret, err := provider.Get(ctx, "vault/item/field")
if err != nil {
    if errors.Is(err, vault.ErrSecretNotFound) {
        // Secret doesn't exist
    } else if errors.Is(err, vault.ErrAccessDenied) {
        // No permission to access
    } else {
        // Other error
    }
}
```

## Testing

```bash
# Unit tests
go test -v ./...

# Integration tests (requires credentials)
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
export OP_TEST_VAULT_NAME="Test Vault"
go test -tags=integration -v ./...
```

## Related Projects

- [OmniVault](https://github.com/agentplexus/omnivault) - Core vault interface
- [omnivault-aws](https://github.com/agentplexus/omnivault-aws) - AWS Secrets Manager & Parameter Store
- [omnivault-keyring](https://github.com/agentplexus/omnivault-keyring) - OS Keychain integration
- [1Password Go SDK](https://github.com/1Password/onepassword-sdk-go) - Official 1Password SDK

## License

MIT License - see [LICENSE](LICENSE) for details.
