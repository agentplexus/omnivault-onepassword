package onepassword

import (
	"errors"
	"strings"

	"github.com/agentplexus/omnivault/vault"
)

// mapError converts 1Password SDK errors to OmniVault errors.
func mapError(operation string, path string, err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Map common error patterns to vault errors
	switch {
	case containsAny(errStr,
		"itemNotFound",
		"vaultNotFound",
		"fieldNotFound",
		"noMatchingSections",
		"item not found",
		"vault not found"):
		return vault.NewVaultError(operation, path, ProviderName, vault.ErrSecretNotFound)

	case containsAny(errStr,
		"unauthorized",
		"forbidden",
		"access denied",
		"AccessDenied",
		"invalid service account token",
		"authentication failed"):
		return vault.NewVaultError(operation, path, ProviderName, vault.ErrAccessDenied)

	case containsAny(errStr,
		"tooManyVaults",
		"tooManyItems",
		"tooManyMatchingFields"):
		return vault.NewVaultError(operation, path, ProviderName,
			errors.New("ambiguous path: multiple matches found"))
	}

	// Return original error wrapped in VaultError
	return vault.NewVaultError(operation, path, ProviderName, err)
}

// containsAny returns true if s contains any of the substrings.
func containsAny(s string, substrs ...string) bool {
	sLower := strings.ToLower(s)
	for _, substr := range substrs {
		if strings.Contains(sLower, strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

// isNotFoundError checks if the error indicates a not-found condition.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return containsAny(errStr,
		"itemnotfound",
		"vaultnotfound",
		"fieldnotfound",
		"not found",
	)
}
