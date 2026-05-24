# Release Notes: v0.1.0

**Release Date:** 2026-01-11

Initial release of OmniVault provider for 1Password.

## Highlights

- OmniVault provider for [1Password](https://1password.com/) using the official [1Password Go SDK](https://github.com/1Password/onepassword-sdk-go)

## Features

- **Vault Interface**: Full implementation of OmniVault `vault.Vault` interface
- **CRUD Operations**: Get, Set, Delete, Exists, and List operations
- **Batch Operations**: GetBatch, SetBatch, and DeleteBatch for bulk access
- **Multi-Field Items**: Support for items with multiple fields (username, password, URL, etc.)
- **Field Type Inference**: Automatic detection of field types (Concealed, URL, Phone, TOTP, Text)
- **TOTP Support**: Generation and extraction of TOTP codes
- **Flexible Paths**: Multiple path formats including native `op://` references
- **Caching**: Vault and item name-to-ID resolution with caching
- **Tags**: Tag support with key:value formatting
- **Error Mapping**: Comprehensive error mapping to OmniVault error types

## Path Formats

| Format | Example | Description |
|--------|---------|-------------|
| `vault/item/field` | `Private/API Keys/token` | Full path to a specific field |
| `vault/item` | `Private/Database Creds` | All fields from an item |
| `item/field` | `API Keys/token` | With default vault configured |
| `op://vault/item/field` | `op://Private/API Keys/token` | Native 1Password reference |

## Installation

```bash
go get github.com/agentplexus/omnivault-onepassword@v0.1.0
```

## Quick Start

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
}
```

## Requirements

- Go 1.22 or later
- 1Password account with Service Account access
- Service account token with appropriate vault permissions

## Dependencies

| Module | Version |
|--------|---------|
| `github.com/1password/onepassword-sdk-go` | v0.4.0 |
| `github.com/agentplexus/omnivault` | v0.2.0 |

## Contributors

- [@plexusone](https://github.com/plexusone)

## Links

- [Documentation](https://pkg.go.dev/github.com/agentplexus/omnivault-onepassword)
- [Source Code](https://github.com/agentplexus/omnivault-onepassword)
- [1Password Go SDK](https://github.com/1Password/onepassword-sdk-go)
- [OmniVault](https://github.com/agentplexus/omnivault)
