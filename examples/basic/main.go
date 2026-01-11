// Example: Basic usage of omnivault-onepassword
//
// This example demonstrates how to use the 1Password provider for basic
// secret operations: get, set, list, and delete.
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

	op "github.com/agentplexus/omnivault-onepassword"
	"github.com/agentplexus/omnivault/vault"
)

func main() {
	// Create provider from environment
	provider, err := op.NewFromEnv()
	if err != nil {
		log.Fatalf("Failed to create provider: %v", err)
	}
	defer func() {
		if err := provider.Close(); err != nil {
			log.Printf("Failed to close provider: %v", err)
		}
	}()

	ctx := context.Background()

	// Get vault name from environment or use default
	vaultName := os.Getenv("OP_VAULT_NAME")
	if vaultName == "" {
		vaultName = "Private"
	}

	// Example 1: List all items in a vault
	fmt.Println("=== Listing items ===")
	items, err := provider.List(ctx, vaultName+"/")
	if err != nil {
		log.Printf("List failed: %v", err)
	} else {
		for _, item := range items {
			fmt.Printf("  - %s\n", item)
		}
	}

	// Example 2: Get a secret (if you have one)
	fmt.Println("\n=== Getting a secret ===")
	secretPath := os.Getenv("OP_SECRET_PATH")
	if secretPath != "" {
		secret, err := provider.Get(ctx, secretPath)
		if err != nil {
			log.Printf("Get failed: %v", err)
		} else {
			fmt.Printf("Path: %s\n", secret.Metadata.Path)
			fmt.Printf("Value: %s\n", maskSecret(secret.Value))
			fmt.Printf("Fields:\n")
			for name, value := range secret.Fields {
				fmt.Printf("  %s: %s\n", name, maskSecret(value))
			}
		}
	} else {
		fmt.Println("Set OP_SECRET_PATH to test Get operation")
	}

	// Example 3: Create a test item (optional)
	if os.Getenv("OP_CREATE_TEST") == "true" {
		fmt.Println("\n=== Creating test item ===")
		testPath := vaultName + "/omnivault-test-item"

		err := provider.Set(ctx, testPath, &vault.Secret{
			Fields: map[string]string{
				"username": "test-user",
				"password": "test-password-123",
				"url":      "https://example.com",
			},
			Metadata: vault.Metadata{
				Tags: map[string]string{
					"created-by": "omnivault-example",
				},
			},
		})
		if err != nil {
			log.Printf("Set failed: %v", err)
		} else {
			fmt.Printf("Created: %s\n", testPath)

			// Read it back
			secret, err := provider.Get(ctx, testPath)
			if err != nil {
				log.Printf("Get after create failed: %v", err)
			} else {
				fmt.Printf("Retrieved username: %s\n", secret.Fields["username"])
			}

			// Clean up
			if os.Getenv("OP_KEEP_TEST") != "true" {
				fmt.Println("\nCleaning up test item...")
				if err := provider.Delete(ctx, testPath); err != nil {
					log.Printf("Delete failed: %v", err)
				} else {
					fmt.Println("Deleted test item")
				}
			}
		}
	}

	// Example 4: Check capabilities
	fmt.Println("\n=== Provider capabilities ===")
	caps := provider.Capabilities()
	fmt.Printf("Read: %v\n", caps.Read)
	fmt.Printf("Write: %v\n", caps.Write)
	fmt.Printf("Delete: %v\n", caps.Delete)
	fmt.Printf("List: %v\n", caps.List)
	fmt.Printf("MultiField: %v\n", caps.MultiField)
	fmt.Printf("Batch: %v\n", caps.Batch)
}

// maskSecret masks a secret value for display
func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
}
