# Release Notes: v0.2.0

**Release Date:** 2026-03-14

Module migrated to new GitHub organization with 1Password SDK v0.4.0 compatibility updates.

## Highlights

- Module migrated to new GitHub organization: `github.com/plexusone/omnivault-onepassword`
- Updated for 1Password SDK v0.4.0 API breaking changes

## Breaking Changes

- **Module Path Changed**: Import path changed from `github.com/agentplexus/omnivault-onepassword` to `github.com/plexusone/omnivault-onepassword`

## Upgrade Guide

### 1. Update Import Paths

Replace all imports in your Go files:

```go
// Before
import op "github.com/agentplexus/omnivault-onepassword"

// After
import op "github.com/plexusone/omnivault-onepassword"
```

### 2. Update go.mod

```bash
# Remove old module
go mod edit -droprequire github.com/agentplexus/omnivault-onepassword

# Add new module
go get github.com/plexusone/omnivault-onepassword@v0.2.0
```

### 3. Tidy Dependencies

```bash
go mod tidy
```

## Changes

### SDK Compatibility

- SDK API calls updated from field access to method calls (`client.Items` to `client.Items()`)
- List operations changed from iterator pattern to direct slice returns

### Dependencies

| Module | Change |
|--------|--------|
| `github.com/plexusone/omnivault` | v0.2.2 → v0.3.0 |
| `github.com/1password/onepassword-sdk-go` | v0.4.0 (maintained) |

### Infrastructure

- CI workflows migrated to shared workflow references
- Workflows renamed for consistency: `go-ci.yaml`, `go-lint.yaml`, `go-sast-codeql.yaml`

### Documentation

- README badges and shields updated for new organization

## Installation

```bash
go get github.com/plexusone/omnivault-onepassword@v0.2.0
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    op "github.com/plexusone/omnivault-onepassword"
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

- Go 1.22 or later (Go 1.24+ recommended for 1Password SDK)
- 1Password account with Service Account access
- Service account token with appropriate vault permissions

## Contributors

- [@plexusone](https://github.com/plexusone)

## Links

- [Documentation](https://pkg.go.dev/github.com/plexusone/omnivault-onepassword)
- [Source Code](https://github.com/plexusone/omnivault-onepassword)
- [Changelog](https://github.com/plexusone/omnivault-onepassword/blob/main/CHANGELOG.md)
- [1Password Go SDK](https://github.com/1Password/onepassword-sdk-go)
- [OmniVault](https://github.com/plexusone/omnivault)
