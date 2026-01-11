package onepassword

import (
	"context"

	"github.com/agentplexus/omnivault/vault"
)

// GetBatch retrieves multiple secrets in a single operation.
// This implements the vault.BatchVault interface.
//
// Note: The 1Password SDK v0.1.x doesn't support batch resolution,
// so this is implemented as sequential Resolve calls.
func (p *Provider) GetBatch(ctx context.Context, paths []string) (map[string]*vault.Secret, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return nil, vault.NewVaultError("GetBatch", "", ProviderName, vault.ErrClosed)
	}

	if len(paths) == 0 {
		return make(map[string]*vault.Secret), nil
	}

	results := make(map[string]*vault.Secret)

	// Process each path individually
	// Note: We release the read lock for each Get call since Get acquires its own lock
	p.mu.RUnlock()
	defer p.mu.RLock()

	for _, path := range paths {
		secret, err := p.Get(ctx, path)
		if err == nil {
			results[path] = secret
		}
		// Skip failed resolutions silently for batch operations
	}

	return results, nil
}

// SetBatch stores multiple secrets in a single operation.
// Note: 1Password SDK doesn't support batch writes, so this is implemented
// as sequential operations.
func (p *Provider) SetBatch(ctx context.Context, secrets map[string]*vault.Secret) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return vault.NewVaultError("SetBatch", "", ProviderName, vault.ErrClosed)
	}

	// Unlock for individual operations (they acquire their own locks)
	p.mu.Unlock()
	defer p.mu.Lock()

	var lastErr error
	for path, secret := range secrets {
		if err := p.Set(ctx, path, secret); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// DeleteBatch removes multiple secrets in a single operation.
// Note: 1Password SDK doesn't support batch deletes, so this is implemented
// as sequential operations.
func (p *Provider) DeleteBatch(ctx context.Context, paths []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return vault.NewVaultError("DeleteBatch", "", ProviderName, vault.ErrClosed)
	}

	// Unlock for individual operations (they acquire their own locks)
	p.mu.Unlock()
	defer p.mu.Lock()

	var lastErr error
	for _, path := range paths {
		if err := p.Delete(ctx, path); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// Ensure Provider implements vault.BatchVault.
var _ vault.BatchVault = (*Provider)(nil)
