# Release Notes: v0.3.0

**Release Date:** 2026-05-03

Module renamed to `omni-onepassword` and restructured as a monorepo following the omni-<provider> pattern.

## Highlights

- Renamed to `omni-onepassword` following the omni-<provider> pattern (like omni-aws)
- Restructured as monorepo with `omnivault/` subdirectory

## Breaking Changes

- **Module Path Changed**: `github.com/plexusone/omnivault-onepassword` → `github.com/plexusone/omni-onepassword`
- **Import Path Changed**: Provider now at `github.com/plexusone/omni-onepassword/omnivault`

## Upgrade Guide

### 1. Update Import Paths

Replace all imports in your Go files:

```go
// Before
import op "github.com/plexusone/omnivault-onepassword"

// After
import op "github.com/plexusone/omni-onepassword/omnivault"
```

### 2. Update go.mod

```bash
# Remove old module
go mod edit -droprequire github.com/plexusone/omnivault-onepassword

# Add new module
go get github.com/plexusone/omni-onepassword/omnivault@v0.3.0
```

### 3. Tidy Dependencies

```bash
go mod tidy
```

## Changes

### Structure

The module now follows the omni-<provider> monorepo pattern:

```
omni-onepassword/
├── README.md           # Root README with quick start
├── go.mod              # Single module at root
├── omnivault/
│   ├── README.md       # Detailed provider documentation
│   ├── onepassword.go  # Provider implementation
│   ├── config.go       # Configuration
│   └── examples/       # Usage examples
└── CHANGELOG.md
```

### Configuration

- Integration name changed from `omnivault-onepassword` to `omni-onepassword`

### Documentation

- New root README.md following omni-aws pattern
- Updated omnivault/README.md with new import paths and related projects

## Installation

```bash
go get github.com/plexusone/omni-onepassword/omnivault@v0.3.0
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    op "github.com/plexusone/omni-onepassword/omnivault"
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

## Requirements

- Go 1.22 or later (Go 1.24+ recommended for 1Password SDK)
- 1Password account with Service Account access
- Service account token with appropriate vault permissions

## Contributors

- [@plexusone](https://github.com/plexusone)

## Links

- [Documentation](https://pkg.go.dev/github.com/plexusone/omni-onepassword/omnivault)
- [Source Code](https://github.com/plexusone/omni-onepassword)
- [Changelog](https://github.com/plexusone/omni-onepassword/blob/main/CHANGELOG.md)
- [1Password Go SDK](https://github.com/1Password/onepassword-sdk-go)
- [OmniVault](https://github.com/plexusone/omnivault)
- [omni-aws](https://github.com/plexusone/omni-aws) - AWS providers (Secrets Manager, Parameter Store, S3, Bedrock)
