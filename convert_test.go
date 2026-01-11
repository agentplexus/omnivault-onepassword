package onepassword

import (
	"testing"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/agentplexus/omnivault/vault"
)

func TestInferFieldType(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  op.ItemFieldType
	}{
		{"password", "secret123", op.ItemFieldTypeConcealed},
		{"api_key", "key123", op.ItemFieldTypeConcealed},
		{"secret_token", "tok123", op.ItemFieldTypeConcealed},
		{"credential", "cred123", op.ItemFieldTypeConcealed},
		{"website", "https://example.com", op.ItemFieldTypeURL},
		{"url", "https://example.com", op.ItemFieldTypeURL},
		{"endpoint", "https://api.example.com", op.ItemFieldTypeURL},
		{"phone", "+1234567890", op.ItemFieldTypePhone},
		{"mobile", "+1234567890", op.ItemFieldTypePhone},
		{"telephone", "+1234567890", op.ItemFieldTypePhone},
		{"totp_field", "otpauth://totp/test?secret=abc", op.ItemFieldTypeTOTP},
		{"notes", "some text", op.ItemFieldTypeText},
		{"description", "some description", op.ItemFieldTypeText},
		{"username", "user123", op.ItemFieldTypeText},
		{"email", "user@example.com", op.ItemFieldTypeText}, // Email type not in v0.1.3
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inferFieldType(tt.name, tt.value); got != tt.want {
				t.Errorf("inferFieldType(%q, %q) = %v, want %v", tt.name, tt.value, got, tt.want)
			}
		})
	}
}

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"password", "password"},
		{"API Key", "api_key"},
		{"api-key", "api_key"},
		{"Some Field!", "some_field"},
		{"field@123", "field123"},
		{"   spaces   ", "spaces"},
		{"", "field"},
		{"123", "123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeID(tt.name); got != tt.want {
				t.Errorf("sanitizeID(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestItemToSecret(t *testing.T) {
	item := op.Item{
		ID:       "item123",
		VaultID:  "vault456",
		Title:    "Test Item",
		Category: op.ItemCategoryLogin,
		Version:  5,
		Fields: []op.ItemField{
			{ID: "username", Title: "username", Value: "testuser", FieldType: op.ItemFieldTypeText},
			{ID: "password", Title: "password", Value: "secret123", FieldType: op.ItemFieldTypeConcealed},
			{ID: "url", Title: "website", Value: "https://example.com", FieldType: op.ItemFieldTypeURL},
		},
		Tags: []string{"env:prod", "team:backend"},
	}

	secret := itemToSecret(item, "Private/Test Item")

	// Check primary value (should be password)
	if secret.Value != "secret123" {
		t.Errorf("Expected Value = 'secret123', got %q", secret.Value)
	}

	// Check fields
	if secret.Fields["username"] != "testuser" {
		t.Errorf("Expected Fields[username] = 'testuser', got %q", secret.Fields["username"])
	}
	if secret.Fields["password"] != "secret123" {
		t.Errorf("Expected Fields[password] = 'secret123', got %q", secret.Fields["password"])
	}
	if secret.Fields["website"] != "https://example.com" {
		t.Errorf("Expected Fields[website] = 'https://example.com', got %q", secret.Fields["website"])
	}

	// Check metadata
	if secret.Metadata.Provider != ProviderName {
		t.Errorf("Expected Provider = %q, got %q", ProviderName, secret.Metadata.Provider)
	}
	if secret.Metadata.Path != "Private/Test Item" {
		t.Errorf("Expected Path = 'Private/Test Item', got %q", secret.Metadata.Path)
	}
	if secret.Metadata.Version != "5" {
		t.Errorf("Expected Version = '5', got %q", secret.Metadata.Version)
	}

	// Check extra metadata
	if secret.Metadata.Extra["vaultId"] != "vault456" {
		t.Errorf("Expected Extra[vaultId] = 'vault456', got %v", secret.Metadata.Extra["vaultId"])
	}
	if secret.Metadata.Extra["itemId"] != "item123" {
		t.Errorf("Expected Extra[itemId] = 'item123', got %v", secret.Metadata.Extra["itemId"])
	}

	// Check tags
	if secret.Metadata.Tags["env"] != "prod" {
		t.Errorf("Expected Tags[env] = 'prod', got %q", secret.Metadata.Tags["env"])
	}
	if secret.Metadata.Tags["team"] != "backend" {
		t.Errorf("Expected Tags[team] = 'backend', got %q", secret.Metadata.Tags["team"])
	}
}

func TestItemToSecret_NoConcealedField(t *testing.T) {
	item := op.Item{
		ID:      "item123",
		VaultID: "vault456",
		Title:   "Note Item",
		Fields: []op.ItemField{
			{ID: "text", Title: "text", Value: "some text", FieldType: op.ItemFieldTypeText},
		},
	}

	secret := itemToSecret(item, "Private/Note Item")

	// Should fall back to first field value (Notes not available in v0.1.3)
	if secret.Value != "some text" {
		t.Errorf("Expected Value = 'some text', got %q", secret.Value)
	}
}

func TestItemToSecret_NoNotesOrConcealed(t *testing.T) {
	item := op.Item{
		ID:      "item123",
		VaultID: "vault456",
		Title:   "Text Item",
		Fields: []op.ItemField{
			{ID: "text", Title: "text", Value: "some text", FieldType: op.ItemFieldTypeText},
		},
	}

	secret := itemToSecret(item, "Private/Text Item")

	// Should fall back to first field value
	if secret.Value != "some text" {
		t.Errorf("Expected Value = 'some text', got %q", secret.Value)
	}
}

func TestSecretToFields(t *testing.T) {
	t.Run("with specific field name", func(t *testing.T) {
		secret := &vault.Secret{Value: "mytoken123"}
		fields := secretToFields(secret, "api_key")

		if len(fields) != 1 {
			t.Fatalf("Expected 1 field, got %d", len(fields))
		}
		if fields[0].Title != "api_key" {
			t.Errorf("Expected Title = 'api_key', got %q", fields[0].Title)
		}
		if fields[0].Value != "mytoken123" {
			t.Errorf("Expected Value = 'mytoken123', got %q", fields[0].Value)
		}
		if fields[0].FieldType != op.ItemFieldTypeConcealed {
			t.Errorf("Expected FieldType = Concealed, got %v", fields[0].FieldType)
		}
	})

	t.Run("with multiple fields", func(t *testing.T) {
		secret := &vault.Secret{
			Fields: map[string]string{
				"username": "user123",
				"password": "secret123",
				"url":      "https://example.com",
			},
		}
		fields := secretToFields(secret, "")

		if len(fields) != 3 {
			t.Fatalf("Expected 3 fields, got %d", len(fields))
		}

		fieldMap := make(map[string]op.ItemField)
		for _, f := range fields {
			fieldMap[f.Title] = f
		}

		if fieldMap["username"].FieldType != op.ItemFieldTypeText {
			t.Errorf("Expected username FieldType = Text, got %v", fieldMap["username"].FieldType)
		}
		if fieldMap["password"].FieldType != op.ItemFieldTypeConcealed {
			t.Errorf("Expected password FieldType = Concealed, got %v", fieldMap["password"].FieldType)
		}
		if fieldMap["url"].FieldType != op.ItemFieldTypeURL {
			t.Errorf("Expected url FieldType = URL, got %v", fieldMap["url"].FieldType)
		}
	})

	t.Run("with value only", func(t *testing.T) {
		secret := &vault.Secret{Value: "standalone-value"}
		fields := secretToFields(secret, "")

		if len(fields) != 1 {
			t.Fatalf("Expected 1 field, got %d", len(fields))
		}
		if fields[0].Title != "password" {
			t.Errorf("Expected Title = 'password', got %q", fields[0].Title)
		}
		if fields[0].Value != "standalone-value" {
			t.Errorf("Expected Value = 'standalone-value', got %q", fields[0].Value)
		}
	})
}

func TestTagsToStrings(t *testing.T) {
	tests := []struct {
		name string
		tags map[string]string
		want int // expected number of tags
	}{
		{"nil tags", nil, 0},
		{"empty tags", map[string]string{}, 0},
		{"key-value tags", map[string]string{"env": "prod", "team": "backend"}, 2},
		{"key-only tags", map[string]string{"important": "", "urgent": ""}, 2},
		{"mixed tags", map[string]string{"env": "prod", "urgent": ""}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tagsToStrings(tt.tags)
			if len(got) != tt.want {
				t.Errorf("tagsToStrings() returned %d tags, want %d", len(got), tt.want)
			}
		})
	}
}
