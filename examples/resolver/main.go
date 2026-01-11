// Example: Using omnivault-onepassword with OmniVault resolver
//
// This example demonstrates how to use the 1Password provider with
// the OmniVault resolver for URI-based secret access.
//
// Prerequisites:
//   - Set OP_SERVICE_ACCOUNT_TOKEN environment variable
//   - Have a vault accessible to the service account
//
// Run with:
//
//	export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
//	go run main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/agentplexus/omnivault"
	op "github.com/agentplexus/omnivault-onepassword"
)

func main() {
	ctx := context.Background()

	// Create 1Password provider
	opProvider, err := op.NewFromEnv()
	if err != nil {
		log.Fatalf("Failed to create 1Password provider: %v", err)
	}
	defer func() {
		if err := opProvider.Close(); err != nil {
			log.Printf("Failed to close provider: %v", err)
		}
	}()

	// Create resolver and register providers
	resolver := omnivault.NewResolver()
	resolver.Register("op", opProvider)

	// You could also register other providers:
	// resolver.Register("env", envProvider)
	// resolver.Register("aws", awsProvider)

	fmt.Println("=== OmniVault Resolver Demo ===")
	fmt.Println()
	fmt.Println("Registered providers:")
	fmt.Println("  - op:// -> 1Password")
	fmt.Println()

	// Example: Resolve a secret using op:// URI
	secretURI := os.Getenv("OP_SECRET_URI")
	if secretURI == "" {
		secretURI = "op://Private/Example Item/password" //nolint:gosec // G101: example URI, not a credential
	}

	fmt.Printf("Resolving: %s\n", secretURI)

	value, err := resolver.Resolve(ctx, secretURI)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		fmt.Println()
		fmt.Println("Try setting OP_SECRET_URI to a valid secret reference:")
		fmt.Println("  export OP_SECRET_URI=\"op://YourVault/YourItem/field\"")
	} else {
		fmt.Printf("  Value: %s\n", maskSecret(value))
	}

	// Example: Using native op:// references
	fmt.Println()
	fmt.Println("The resolver supports native 1Password references:")
	fmt.Println("  op://vault/item/field")
	fmt.Println("  op://vault/item/section/field")
	fmt.Println()
	fmt.Println("Example URIs:")
	fmt.Println("  op://Private/GitHub/token")
	fmt.Println("  op://Work/Database/prod/password")
	fmt.Println("  op://Shared/AWS Credentials/access_key")
}

// maskSecret masks a secret value for display
func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
}
