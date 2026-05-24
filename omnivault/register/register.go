// Package register provides automatic registration of the 1Password provider
// with omnivault's provider registry.
//
// Import this package for side effects to enable 1Password support in
// omnivault.VaultFromURI:
//
//	import _ "github.com/plexusone/omni-onepassword/omnivault/register"
//
//	// Now you can use op:// URIs
//	v, err := omnivault.VaultFromURI("op://MyVault")
//
// Prerequisites:
//   - Set OP_SERVICE_ACCOUNT_TOKEN environment variable
//   - Have a vault accessible to the service account
package register

import (
	"strings"

	onepassword "github.com/plexusone/omni-onepassword/omnivault"
	"github.com/plexusone/omnivault"
	"github.com/plexusone/omnivault/vault"
)

func init() {
	omnivault.RegisterProvider("op", factory)
}

func factory(uri string) (vault.Vault, error) {
	// Parse: op://VaultName or op://VaultName/item
	// Extract default vault from URI if provided
	path := strings.TrimPrefix(uri, "op://")
	config := onepassword.Config{}
	if path != "" {
		// First path component is the default vault
		parts := strings.SplitN(path, "/", 2)
		config.DefaultVaultName = parts[0]
	}
	return onepassword.New(config)
}
