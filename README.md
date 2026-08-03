# Omni-OnePassword

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/plexusone/omni-onepassword/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/plexusone/omni-onepassword/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/plexusone/omni-onepassword/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/plexusone/omni-onepassword/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/plexusone/omni-onepassword/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/plexusone/omni-onepassword/actions/workflows/go-sast-codeql.yaml
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/plexusone/omni-onepassword
 [docs-godoc-url]: https://pkg.go.dev/github.com/plexusone/omni-onepassword
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/plexusone/omni-onepassword/blob/main/LICENSE

1Password provider packages for [PlexusOne](https://github.com/plexusone) libraries.

## Modules

This repository contains Go modules for 1Password integrations:

| Module | Description | Install |
|--------|-------------|---------|
| [`omnivault`](omnivault/) | 1Password provider for [omnivault](https://github.com/plexusone/omnivault) | `go get github.com/plexusone/omni-onepassword/omnivault` |

## Quick Start

### OmniVault - 1Password Provider

```go
import (
    op "github.com/plexusone/omni-onepassword/omnivault"
)

// Create provider (uses OP_SERVICE_ACCOUNT_TOKEN env var)
provider, err := op.NewFromEnv()
if err != nil {
    log.Fatal(err)
}
defer provider.Close()

// Get a secret
secret, err := provider.Get(ctx, "Private/API Keys/github-token")
fmt.Println("Token:", secret.Value)

// Get multi-field item
creds, err := provider.Get(ctx, "Private/Database/prod")
fmt.Println("Username:", creds.Fields["username"])
fmt.Println("Password:", creds.Fields["password"])
```

See [omnivault/README.md](omnivault/README.md) for full documentation including path formats, batch operations, and OmniVault resolver integration.

## Authentication

Set the `OP_SERVICE_ACCOUNT_TOKEN` environment variable with your 1Password service account token:

```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
```

Create a service account at: https://my.1password.com/developer-tools/infrastructure-secrets/serviceaccount/

## License

MIT
