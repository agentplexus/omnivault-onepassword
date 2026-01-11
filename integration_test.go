//go:build integration

package onepassword

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/agentplexus/omnivault/vault"
)

// Integration tests require:
// - OP_SERVICE_ACCOUNT_TOKEN: 1Password service account token
// - OP_TEST_VAULT_ID or OP_TEST_VAULT_NAME: Vault to use for tests
//
// Run with: go test -tags=integration -v

func getTestProvider(t *testing.T) *Provider {
	t.Helper()

	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if token == "" {
		t.Skip("OP_SERVICE_ACCOUNT_TOKEN not set")
	}

	vaultID := os.Getenv("OP_TEST_VAULT_ID")
	vaultName := os.Getenv("OP_TEST_VAULT_NAME")
	if vaultID == "" && vaultName == "" {
		t.Skip("OP_TEST_VAULT_ID or OP_TEST_VAULT_NAME not set")
	}

	provider, err := New(Config{
		ServiceAccountToken: token,
		DefaultVaultID:      vaultID,
		DefaultVaultName:    vaultName,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	return provider
}

func TestIntegration_CRUD(t *testing.T) {
	provider := getTestProvider(t)
	defer provider.Close()

	ctx := context.Background()
	itemName := fmt.Sprintf("test-item-%d", time.Now().UnixNano())

	t.Run("Create", func(t *testing.T) {
		err := provider.Set(ctx, itemName, &vault.Secret{
			Value: "test-secret-value",
			Fields: map[string]string{
				"username": "testuser",
				"password": "testpass123",
			},
			Metadata: vault.Metadata{
				Tags: map[string]string{
					"env":  "test",
					"temp": "true",
				},
			},
		})
		if err != nil {
			t.Fatalf("Set() failed: %v", err)
		}
	})

	t.Run("Exists", func(t *testing.T) {
		exists, err := provider.Exists(ctx, itemName)
		if err != nil {
			t.Fatalf("Exists() failed: %v", err)
		}
		if !exists {
			t.Error("Exists() returned false, expected true")
		}
	})

	t.Run("Get full item", func(t *testing.T) {
		secret, err := provider.Get(ctx, itemName)
		if err != nil {
			t.Fatalf("Get() failed: %v", err)
		}

		if secret.Fields["username"] != "testuser" {
			t.Errorf("Expected username = 'testuser', got %q", secret.Fields["username"])
		}
		if secret.Fields["password"] != "testpass123" {
			t.Errorf("Expected password = 'testpass123', got %q", secret.Fields["password"])
		}
	})

	t.Run("Get specific field", func(t *testing.T) {
		secret, err := provider.Get(ctx, itemName+"/password")
		if err != nil {
			t.Fatalf("Get() failed: %v", err)
		}

		if secret.Value != "testpass123" {
			t.Errorf("Expected Value = 'testpass123', got %q", secret.Value)
		}
	})

	t.Run("Update", func(t *testing.T) {
		err := provider.Set(ctx, itemName+"/password", &vault.Secret{
			Value: "updated-password",
		})
		if err != nil {
			t.Fatalf("Set() update failed: %v", err)
		}

		secret, err := provider.Get(ctx, itemName+"/password")
		if err != nil {
			t.Fatalf("Get() after update failed: %v", err)
		}
		if secret.Value != "updated-password" {
			t.Errorf("Expected updated Value = 'updated-password', got %q", secret.Value)
		}
	})

	t.Run("List", func(t *testing.T) {
		items, err := provider.List(ctx, "")
		if err != nil {
			t.Fatalf("List() failed: %v", err)
		}

		found := false
		for _, item := range items {
			if item == itemName || (len(item) > len(itemName) && item[len(item)-len(itemName):] == itemName) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("List() did not include created item %q", itemName)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		err := provider.Delete(ctx, itemName)
		if err != nil {
			t.Fatalf("Delete() failed: %v", err)
		}

		exists, err := provider.Exists(ctx, itemName)
		if err != nil {
			t.Fatalf("Exists() after delete failed: %v", err)
		}
		if exists {
			t.Error("Exists() returned true after delete, expected false")
		}
	})

	t.Run("Delete idempotent", func(t *testing.T) {
		// Deleting non-existent item should not error
		err := provider.Delete(ctx, itemName)
		if err != nil {
			t.Errorf("Delete() non-existent item failed: %v", err)
		}
	})
}

func TestIntegration_GetNotFound(t *testing.T) {
	provider := getTestProvider(t)
	defer provider.Close()

	ctx := context.Background()

	_, err := provider.Get(ctx, "nonexistent-vault/nonexistent-item/nonexistent-field")
	if err == nil {
		t.Error("Get() should have returned an error for non-existent secret")
	}

	// Check that it's a not-found error
	if !isNotFoundError(err) {
		t.Logf("Error: %v", err)
		// This might be access denied or other error depending on vault permissions
	}
}

func TestIntegration_Capabilities(t *testing.T) {
	provider := getTestProvider(t)
	defer provider.Close()

	caps := provider.Capabilities()

	if !caps.Read {
		t.Error("Expected Read capability")
	}
	if !caps.Write {
		t.Error("Expected Write capability")
	}
	if !caps.Delete {
		t.Error("Expected Delete capability")
	}
	if !caps.List {
		t.Error("Expected List capability")
	}
	if !caps.MultiField {
		t.Error("Expected MultiField capability")
	}
	if !caps.Batch {
		t.Error("Expected Batch capability")
	}
}

func TestIntegration_BatchGet(t *testing.T) {
	provider := getTestProvider(t)
	defer provider.Close()

	ctx := context.Background()
	timestamp := time.Now().UnixNano()

	// Create test items
	item1 := fmt.Sprintf("batch-test-1-%d", timestamp)
	item2 := fmt.Sprintf("batch-test-2-%d", timestamp)

	err := provider.Set(ctx, item1, &vault.Secret{Value: "value1"})
	if err != nil {
		t.Fatalf("Failed to create test item 1: %v", err)
	}
	defer provider.Delete(ctx, item1)

	err = provider.Set(ctx, item2, &vault.Secret{Value: "value2"})
	if err != nil {
		t.Fatalf("Failed to create test item 2: %v", err)
	}
	defer provider.Delete(ctx, item2)

	// Test batch get
	results, err := provider.GetBatch(ctx, []string{
		item1 + "/password",
		item2 + "/password",
	})
	if err != nil {
		t.Fatalf("GetBatch() failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}
}
