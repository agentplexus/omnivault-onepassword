// Package onepassword provides an OmniVault provider for 1Password.
//
// This package implements the vault.Vault interface using the official
// 1Password Go SDK, allowing applications to access secrets stored in
// 1Password vaults through the unified OmniVault interface.
//
// Authentication requires a 1Password Service Account token. Create one at:
// https://my.1password.com/developer-tools/infrastructure-secrets/serviceaccount/
//
// Basic usage:
//
//	provider, err := onepassword.New(onepassword.Config{
//	    ServiceAccountToken: os.Getenv("OP_SERVICE_ACCOUNT_TOKEN"),
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer provider.Close()
//
//	secret, err := provider.Get(ctx, "Private/API Keys/github-token")
//
// With OmniVault resolver:
//
//	resolver := omnivault.NewResolver()
//	resolver.Register("op", provider)
//	value, err := resolver.Resolve(ctx, "op://Private/API Keys/github-token")
package onepassword

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/agentplexus/omnivault/vault"
)

// Provider implements vault.Vault for 1Password.
type Provider struct {
	client *op.Client
	config Config

	// vaultCache caches vault name -> ID mappings
	vaultCache map[string]string
	vaultMu    sync.RWMutex

	mu     sync.RWMutex
	closed bool
}

// New creates a new 1Password provider with the given configuration.
func New(config Config) (*Provider, error) {
	return NewWithContext(context.Background(), config)
}

// NewWithContext creates a new 1Password provider with context.
func NewWithContext(ctx context.Context, config Config) (*Provider, error) {
	config = config.withDefaults()

	// Get token from environment if not provided
	token := config.ServiceAccountToken
	if token == "" {
		token = os.Getenv(EnvServiceAccountToken)
	}
	if token == "" {
		return nil, fmt.Errorf("service account token is required: set Config.ServiceAccountToken or %s environment variable", EnvServiceAccountToken)
	}

	// Create 1Password client
	client, err := op.NewClient(ctx,
		op.WithServiceAccountToken(token),
		op.WithIntegrationInfo(config.IntegrationName, config.IntegrationVersion),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create 1Password client: %w", err)
	}

	return &Provider{
		client:     client,
		config:     config,
		vaultCache: make(map[string]string),
	}, nil
}

// NewFromEnv creates a new provider using the OP_SERVICE_ACCOUNT_TOKEN environment variable.
func NewFromEnv() (*Provider, error) {
	return New(Config{})
}

// Get retrieves a secret from 1Password.
//
// Path formats supported:
//   - "vault/item/field" - returns the specific field value
//   - "vault/item" - returns the item with all fields
//   - "item/field" - uses default vault (if configured)
//   - "op://vault/item/field" - native 1Password secret reference
func (p *Provider) Get(ctx context.Context, path string) (*vault.Secret, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return nil, vault.NewVaultError("Get", path, ProviderName, vault.ErrClosed)
	}

	parsed, err := ParsePath(path, p.getDefaultVault())
	if err != nil {
		return nil, vault.NewVaultError("Get", path, ProviderName, err)
	}

	// If field is specified, use Secrets().Resolve() for direct field access
	if parsed.Field != "" {
		return p.resolveField(ctx, parsed)
	}

	// Otherwise get the full item
	return p.getItem(ctx, parsed)
}

// resolveField retrieves a single field using the Secrets API.
func (p *Provider) resolveField(ctx context.Context, parsed *ParsedPath) (*vault.Secret, error) {
	ref := parsed.SecretReference()

	value, err := p.client.Secrets.Resolve(ctx, ref)
	if err != nil {
		return nil, mapError("Get", parsed.String(), err)
	}

	return &vault.Secret{
		Value: value,
		Metadata: vault.Metadata{
			Provider: ProviderName,
			Path:     parsed.String(),
		},
	}, nil
}

// getItem retrieves a full item using the Items API.
func (p *Provider) getItem(ctx context.Context, parsed *ParsedPath) (*vault.Secret, error) {
	// Resolve vault name to ID
	vaultID, err := p.resolveVaultID(ctx, parsed.Vault)
	if err != nil {
		return nil, mapError("Get", parsed.String(), err)
	}

	// Resolve item name to ID
	itemID, err := p.resolveItemID(ctx, vaultID, parsed.Item)
	if err != nil {
		return nil, mapError("Get", parsed.String(), err)
	}

	item, err := p.client.Items.Get(ctx, vaultID, itemID)
	if err != nil {
		return nil, mapError("Get", parsed.String(), err)
	}

	return itemToSecret(item, parsed.String()), nil
}

// Set stores a secret in 1Password.
func (p *Provider) Set(ctx context.Context, path string, secret *vault.Secret) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return vault.NewVaultError("Set", path, ProviderName, vault.ErrClosed)
	}

	parsed, err := ParsePath(path, p.getDefaultVault())
	if err != nil {
		return vault.NewVaultError("Set", path, ProviderName, err)
	}

	// Resolve vault
	vaultID, err := p.resolveVaultID(ctx, parsed.Vault)
	if err != nil {
		return mapError("Set", path, err)
	}

	// Check if item exists
	itemID, err := p.resolveItemID(ctx, vaultID, parsed.Item)
	if err == nil {
		// Update existing item
		return p.updateItem(ctx, vaultID, itemID, parsed, secret)
	}

	// Create new item
	return p.createItem(ctx, vaultID, parsed, secret)
}

// createItem creates a new item in 1Password.
func (p *Provider) createItem(ctx context.Context, vaultID string, parsed *ParsedPath, secret *vault.Secret) error {
	params := op.ItemCreateParams{
		VaultID:  vaultID,
		Title:    parsed.Item,
		Category: p.config.DefaultCategory,
		Fields:   secretToFields(secret, parsed.Field),
	}

	// Add tags from metadata
	if secret.Metadata.Tags != nil {
		params.Tags = tagsToStrings(secret.Metadata.Tags)
	}

	_, err := p.client.Items.Create(ctx, params)
	if err != nil {
		return mapError("Set", parsed.String(), err)
	}

	return nil
}

// updateItem updates an existing item in 1Password.
func (p *Provider) updateItem(ctx context.Context, vaultID, itemID string, parsed *ParsedPath, secret *vault.Secret) error {
	// Get existing item
	item, err := p.client.Items.Get(ctx, vaultID, itemID)
	if err != nil {
		return mapError("Set", parsed.String(), err)
	}

	// Update fields
	if parsed.Field != "" {
		// Update or add specific field
		fieldFound := false
		for i := range item.Fields {
			if item.Fields[i].Title == parsed.Field || item.Fields[i].ID == parsed.Field {
				item.Fields[i].Value = secret.Value
				fieldFound = true
				break
			}
		}
		if !fieldFound {
			item.Fields = append(item.Fields, op.ItemField{
				ID:        sanitizeID(parsed.Field),
				Title:     parsed.Field,
				Value:     secret.Value,
				FieldType: op.ItemFieldTypeConcealed,
			})
		}
	} else {
		// Replace all fields
		item.Fields = secretToFields(secret, "")
	}

	// Update tags if provided
	if secret.Metadata.Tags != nil {
		item.Tags = tagsToStrings(secret.Metadata.Tags)
	}

	_, err = p.client.Items.Put(ctx, item)
	if err != nil {
		return mapError("Set", parsed.String(), err)
	}

	return nil
}

// Delete removes a secret from 1Password.
func (p *Provider) Delete(ctx context.Context, path string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return vault.NewVaultError("Delete", path, ProviderName, vault.ErrClosed)
	}

	parsed, err := ParsePath(path, p.getDefaultVault())
	if err != nil {
		return vault.NewVaultError("Delete", path, ProviderName, err)
	}

	// Resolve vault
	vaultID, err := p.resolveVaultID(ctx, parsed.Vault)
	if err != nil {
		// Vault not found = nothing to delete
		if isNotFoundError(err) {
			return nil
		}
		return mapError("Delete", path, err)
	}

	// Resolve item
	itemID, err := p.resolveItemID(ctx, vaultID, parsed.Item)
	if err != nil {
		// Item not found = nothing to delete
		if isNotFoundError(err) {
			return nil
		}
		return mapError("Delete", path, err)
	}

	err = p.client.Items.Delete(ctx, vaultID, itemID)
	if err != nil {
		// Ignore not found errors
		if isNotFoundError(err) {
			return nil
		}
		return mapError("Delete", path, err)
	}

	return nil
}

// Exists checks if a secret exists in 1Password.
func (p *Provider) Exists(ctx context.Context, path string) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return false, vault.NewVaultError("Exists", path, ProviderName, vault.ErrClosed)
	}

	parsed, err := ParsePath(path, p.getDefaultVault())
	if err != nil {
		return false, vault.NewVaultError("Exists", path, ProviderName, err)
	}

	// Resolve vault
	vaultID, err := p.resolveVaultID(ctx, parsed.Vault)
	if err != nil {
		if isNotFoundError(err) {
			return false, nil
		}
		return false, mapError("Exists", path, err)
	}

	// Resolve item
	_, err = p.resolveItemID(ctx, vaultID, parsed.Item)
	if err != nil {
		if isNotFoundError(err) {
			return false, nil
		}
		return false, mapError("Exists", path, err)
	}

	return true, nil
}

// List returns all secret paths matching the prefix.
func (p *Provider) List(ctx context.Context, prefix string) ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return nil, vault.NewVaultError("List", prefix, ProviderName, vault.ErrClosed)
	}

	var results []string

	// Get all vaults
	vaultsIter, err := p.client.Vaults.ListAll(ctx)
	if err != nil {
		return nil, mapError("List", prefix, err)
	}

	for {
		v, err := vaultsIter.Next()
		if err == op.ErrorIteratorDone {
			break
		}
		if err != nil {
			return nil, mapError("List", prefix, err)
		}

		// Filter by prefix if it specifies a vault
		if prefix != "" && !strings.HasPrefix(v.Title, prefix) && !strings.HasPrefix(prefix, v.Title+"/") {
			continue
		}

		// List items in vault
		itemsIter, err := p.client.Items.ListAll(ctx, v.ID)
		if err != nil {
			// Skip vaults we can't access
			continue
		}

		for {
			item, err := itemsIter.Next()
			if err == op.ErrorIteratorDone {
				break
			}
			if err != nil {
				// Skip items we can't iterate
				break
			}

			path := fmt.Sprintf("%s/%s", v.Title, item.Title)
			if prefix == "" || strings.HasPrefix(path, prefix) {
				results = append(results, path)
			}
		}

		// Cache vault ID
		p.cacheVaultID(v.Title, v.ID)
	}

	return results, nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return ProviderName
}

// Capabilities returns the provider capabilities.
func (p *Provider) Capabilities() vault.Capabilities {
	return vault.Capabilities{
		Read:       true,
		Write:      true,
		Delete:     true,
		List:       true,
		Versioning: false, // SDK doesn't expose version history
		Rotation:   false, // No rotation API in SDK
		Binary:     true,  // Via file attachments
		MultiField: true,  // Items have multiple fields
		Batch:      true,  // ResolveAll() for reads
	}
}

// Close releases resources held by the provider.
func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	// The 1Password client uses a runtime finalizer, no explicit close needed
	return nil
}

// getDefaultVault returns the configured default vault.
func (p *Provider) getDefaultVault() string {
	if p.config.DefaultVaultID != "" {
		return p.config.DefaultVaultID
	}
	return p.config.DefaultVaultName
}

// resolveVaultID resolves a vault name or ID to its ID.
func (p *Provider) resolveVaultID(ctx context.Context, nameOrID string) (string, error) {
	if nameOrID == "" {
		return "", fmt.Errorf("vault name or ID is required")
	}

	// Check cache first
	p.vaultMu.RLock()
	if id, ok := p.vaultCache[nameOrID]; ok {
		p.vaultMu.RUnlock()
		return id, nil
	}
	p.vaultMu.RUnlock()

	// List vaults to find the match
	vaultsIter, err := p.client.Vaults.ListAll(ctx)
	if err != nil {
		return "", err
	}

	for {
		v, err := vaultsIter.Next()
		if err == op.ErrorIteratorDone {
			break
		}
		if err != nil {
			return "", err
		}

		// Cache all vault IDs while we're at it
		p.cacheVaultID(v.Title, v.ID)

		// Check for match by ID or title
		if v.ID == nameOrID || v.Title == nameOrID {
			return v.ID, nil
		}
	}

	return "", fmt.Errorf("vault not found: %s", nameOrID)
}

// resolveItemID resolves an item name or ID to its ID.
func (p *Provider) resolveItemID(ctx context.Context, vaultID, nameOrID string) (string, error) {
	if nameOrID == "" {
		return "", fmt.Errorf("item name or ID is required")
	}

	// List items to find the match
	itemsIter, err := p.client.Items.ListAll(ctx, vaultID)
	if err != nil {
		return "", err
	}

	for {
		item, err := itemsIter.Next()
		if err == op.ErrorIteratorDone {
			break
		}
		if err != nil {
			return "", err
		}

		if item.ID == nameOrID || item.Title == nameOrID {
			return item.ID, nil
		}
	}

	return "", fmt.Errorf("item not found: %s", nameOrID)
}

// cacheVaultID caches a vault name -> ID mapping.
func (p *Provider) cacheVaultID(name, id string) {
	p.vaultMu.Lock()
	p.vaultCache[name] = id
	p.vaultCache[id] = id // Also cache ID -> ID for direct lookups
	p.vaultMu.Unlock()
}

// Ensure Provider implements vault.Vault.
var _ vault.Vault = (*Provider)(nil)
