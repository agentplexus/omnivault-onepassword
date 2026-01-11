package onepassword

import (
	"testing"
)

func TestConfig_withDefaults(t *testing.T) {
	t.Run("applies defaults", func(t *testing.T) {
		cfg := Config{}.withDefaults()

		if cfg.IntegrationName != DefaultIntegrationName {
			t.Errorf("Expected IntegrationName = %q, got %q", DefaultIntegrationName, cfg.IntegrationName)
		}
		if cfg.IntegrationVersion != DefaultIntegrationVersion {
			t.Errorf("Expected IntegrationVersion = %q, got %q", DefaultIntegrationVersion, cfg.IntegrationVersion)
		}
		if cfg.DefaultCategory != CategorySecureNote {
			t.Errorf("Expected DefaultCategory = SecureNote, got %v", cfg.DefaultCategory)
		}
	})

	t.Run("preserves custom values", func(t *testing.T) {
		cfg := Config{
			IntegrationName:    "custom-name",
			IntegrationVersion: "1.0.0",
			DefaultCategory:    CategoryLogin,
		}.withDefaults()

		if cfg.IntegrationName != "custom-name" {
			t.Errorf("Expected IntegrationName = 'custom-name', got %q", cfg.IntegrationName)
		}
		if cfg.IntegrationVersion != "1.0.0" {
			t.Errorf("Expected IntegrationVersion = '1.0.0', got %q", cfg.IntegrationVersion)
		}
		if cfg.DefaultCategory != CategoryLogin {
			t.Errorf("Expected DefaultCategory = Login, got %v", cfg.DefaultCategory)
		}
	})
}

func TestProvider_Name(t *testing.T) {
	p := &Provider{}
	if p.Name() != ProviderName {
		t.Errorf("Expected Name() = %q, got %q", ProviderName, p.Name())
	}
}

func TestProvider_Capabilities(t *testing.T) {
	p := &Provider{}
	caps := p.Capabilities()

	tests := []struct {
		name string
		got  bool
		want bool
	}{
		{"Read", caps.Read, true},
		{"Write", caps.Write, true},
		{"Delete", caps.Delete, true},
		{"List", caps.List, true},
		{"Versioning", caps.Versioning, false},
		{"Rotation", caps.Rotation, false},
		{"Binary", caps.Binary, true},
		{"MultiField", caps.MultiField, true},
		{"Batch", caps.Batch, true},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("Capabilities.%s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

func TestProvider_Close(t *testing.T) {
	p := &Provider{}

	if p.closed {
		t.Error("Provider should not be closed initially")
	}

	err := p.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	if !p.closed {
		t.Error("Provider should be closed after Close()")
	}
}

func TestProvider_getDefaultVault(t *testing.T) {
	t.Run("prefers DefaultVaultID", func(t *testing.T) {
		p := &Provider{
			config: Config{
				DefaultVaultID:   "vault-id",
				DefaultVaultName: "vault-name",
			},
		}

		if got := p.getDefaultVault(); got != "vault-id" {
			t.Errorf("getDefaultVault() = %q, want 'vault-id'", got)
		}
	})

	t.Run("falls back to DefaultVaultName", func(t *testing.T) {
		p := &Provider{
			config: Config{
				DefaultVaultName: "vault-name",
			},
		}

		if got := p.getDefaultVault(); got != "vault-name" {
			t.Errorf("getDefaultVault() = %q, want 'vault-name'", got)
		}
	})

	t.Run("returns empty if neither set", func(t *testing.T) {
		p := &Provider{config: Config{}}

		if got := p.getDefaultVault(); got != "" {
			t.Errorf("getDefaultVault() = %q, want ''", got)
		}
	})
}

func TestNewWithoutToken(t *testing.T) {
	// Ensure no token in environment for this test
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "")

	_, err := New(Config{})
	if err == nil {
		t.Error("New() should return error when no token provided")
	}
}
