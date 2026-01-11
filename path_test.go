package onepassword

import (
	"testing"
)

func TestParsePath(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		defaultVault string
		want         *ParsedPath
		wantErr      bool
	}{
		{
			name: "vault/item/field",
			path: "Private/API Keys/token",
			want: &ParsedPath{
				Vault: "Private",
				Item:  "API Keys",
				Field: "token",
			},
		},
		{
			name: "vault/item",
			path: "Private/Database Creds",
			want: &ParsedPath{
				Vault: "Private",
				Item:  "Database Creds",
			},
		},
		{
			name:         "item/field with default vault",
			path:         "API Keys/token",
			defaultVault: "Private",
			want: &ParsedPath{
				Vault: "Private",
				Item:  "API Keys",
				Field: "token",
			},
		},
		{
			name:         "item only with default vault",
			path:         "API Keys",
			defaultVault: "Private",
			want: &ParsedPath{
				Vault: "Private",
				Item:  "API Keys",
			},
		},
		{
			name: "vault/item/section/field",
			path: "Private/Login/Security/totp",
			want: &ParsedPath{
				Vault:   "Private",
				Item:    "Login",
				Section: "Security",
				Field:   "totp",
			},
		},
		{
			name: "op:// secret reference",
			path: "op://Private/API Keys/token",
			want: &ParsedPath{
				Vault: "Private",
				Item:  "API Keys",
				Field: "token",
			},
		},
		{
			name: "op:// with section",
			path: "op://Private/Login/Security/totp",
			want: &ParsedPath{
				Vault:   "Private",
				Item:    "Login",
				Section: "Security",
				Field:   "totp",
			},
		},
		{
			name: "op:// with query params (stripped)",
			path: "op://Private/Login/totp?attribute=totp",
			want: &ParsedPath{
				Vault: "Private",
				Item:  "Login",
				Field: "totp",
			},
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
		{
			name:    "item only without default vault",
			path:    "API Keys",
			wantErr: true,
		},
		{
			name:    "too many components",
			path:    "a/b/c/d/e",
			wantErr: true,
		},
		{
			name: "handles double slashes",
			path: "Private//API Keys//token",
			want: &ParsedPath{
				Vault: "Private",
				Item:  "API Keys",
				Field: "token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePath(tt.path, tt.defaultVault)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if got.Vault != tt.want.Vault {
				t.Errorf("ParsePath() Vault = %v, want %v", got.Vault, tt.want.Vault)
			}
			if got.Item != tt.want.Item {
				t.Errorf("ParsePath() Item = %v, want %v", got.Item, tt.want.Item)
			}
			if got.Section != tt.want.Section {
				t.Errorf("ParsePath() Section = %v, want %v", got.Section, tt.want.Section)
			}
			if got.Field != tt.want.Field {
				t.Errorf("ParsePath() Field = %v, want %v", got.Field, tt.want.Field)
			}
		})
	}
}

func TestParsedPath_String(t *testing.T) {
	tests := []struct {
		name string
		path ParsedPath
		want string
	}{
		{
			name: "vault/item/field",
			path: ParsedPath{Vault: "Private", Item: "API Keys", Field: "token"},
			want: "Private/API Keys/token",
		},
		{
			name: "vault/item",
			path: ParsedPath{Vault: "Private", Item: "API Keys"},
			want: "Private/API Keys",
		},
		{
			name: "with section",
			path: ParsedPath{Vault: "Private", Item: "Login", Section: "Security", Field: "totp"},
			want: "Private/Login/Security/totp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.path.String(); got != tt.want {
				t.Errorf("ParsedPath.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsedPath_SecretReference(t *testing.T) {
	tests := []struct {
		name string
		path ParsedPath
		want string
	}{
		{
			name: "vault/item/field",
			path: ParsedPath{Vault: "Private", Item: "API Keys", Field: "token"},
			want: "op://Private/API Keys/token",
		},
		{
			name: "vault/item",
			path: ParsedPath{Vault: "Private", Item: "API Keys"},
			want: "op://Private/API Keys",
		},
		{
			name: "with section",
			path: ParsedPath{Vault: "Private", Item: "Login", Section: "Security", Field: "totp"},
			want: "op://Private/Login/Security/totp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.path.SecretReference(); got != tt.want {
				t.Errorf("ParsedPath.SecretReference() = %v, want %v", got, tt.want)
			}
		})
	}
}
