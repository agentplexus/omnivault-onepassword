package onepassword

import (
	"log/slog"
	"time"

	op "github.com/1password/onepassword-sdk-go"
)

const (
	// ProviderName is the name returned by Provider.Name().
	ProviderName = "onepassword"

	// EnvServiceAccountToken is the environment variable for the service account token.
	EnvServiceAccountToken = "OP_SERVICE_ACCOUNT_TOKEN" //nolint:gosec // G101: this is an env var name, not a credential

	// DefaultIntegrationName identifies this integration to 1Password.
	DefaultIntegrationName = "omnivault-onepassword"

	// DefaultIntegrationVersion is the default version string.
	DefaultIntegrationVersion = "0.1.0"
)

// Common item categories re-exported for convenience.
const (
	CategoryLogin          = op.ItemCategoryLogin
	CategorySecureNote     = op.ItemCategorySecureNote
	CategoryAPICredentials = op.ItemCategoryAPICredentials
	CategoryDatabase       = op.ItemCategoryDatabase
	CategoryServer         = op.ItemCategoryServer
	CategoryPassword       = op.ItemCategoryPassword
	CategorySSHKey         = op.ItemCategorySSHKey
)

// Config holds configuration for the 1Password provider.
type Config struct {
	// ServiceAccountToken is the 1Password service account token.
	// Required. Can also be set via OP_SERVICE_ACCOUNT_TOKEN environment variable.
	ServiceAccountToken string

	// IntegrationName identifies this integration to 1Password.
	// Default: "omnivault-onepassword"
	IntegrationName string

	// IntegrationVersion is the version of this integration.
	// Default: "0.1.0"
	IntegrationVersion string

	// DefaultVaultID is used when path doesn't specify a vault.
	// Takes precedence over DefaultVaultName if both are set.
	DefaultVaultID string

	// DefaultVaultName is used when path doesn't specify a vault.
	// Resolved to ID on first use.
	DefaultVaultName string

	// DefaultCategory is the item category for newly created items.
	// Default: CategorySecureNote
	DefaultCategory op.ItemCategory

	// CacheTTL enables caching of vault/item ID lookups.
	// Zero disables caching. Default: 0 (disabled)
	CacheTTL time.Duration

	// Logger for debug output. Optional.
	Logger *slog.Logger
}

// withDefaults returns a copy of the config with default values applied.
func (c Config) withDefaults() Config {
	if c.IntegrationName == "" {
		c.IntegrationName = DefaultIntegrationName
	}
	if c.IntegrationVersion == "" {
		c.IntegrationVersion = DefaultIntegrationVersion
	}
	if c.DefaultCategory == "" {
		c.DefaultCategory = CategorySecureNote
	}
	return c
}
