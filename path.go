package onepassword

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidPath is returned when a path cannot be parsed.
var ErrInvalidPath = errors.New("invalid path format")

// ParsedPath represents a parsed 1Password secret path.
type ParsedPath struct {
	// Vault is the vault name or ID.
	Vault string

	// Item is the item name or ID.
	Item string

	// Section is the section name (optional).
	Section string

	// Field is the field name (optional).
	Field string
}

// String returns the path in canonical format.
func (p *ParsedPath) String() string {
	var parts []string
	if p.Vault != "" {
		parts = append(parts, p.Vault)
	}
	if p.Item != "" {
		parts = append(parts, p.Item)
	}
	if p.Section != "" {
		parts = append(parts, p.Section)
	}
	if p.Field != "" {
		parts = append(parts, p.Field)
	}
	return strings.Join(parts, "/")
}

// SecretReference returns the path as a 1Password secret reference URI.
func (p *ParsedPath) SecretReference() string {
	if p.Field != "" {
		if p.Section != "" {
			return fmt.Sprintf("op://%s/%s/%s/%s", p.Vault, p.Item, p.Section, p.Field)
		}
		return fmt.Sprintf("op://%s/%s/%s", p.Vault, p.Item, p.Field)
	}
	return fmt.Sprintf("op://%s/%s", p.Vault, p.Item)
}

// ParsePath parses a path string into components.
//
// Supported formats:
//   - "vault/item/field" - full path with vault, item, and field
//   - "vault/item" - vault and item (returns all fields)
//   - "item/field" - item and field (uses defaultVault)
//   - "item" - item only (uses defaultVault, returns all fields)
//   - "vault/item/section/field" - full path with section
//   - "op://vault/item/field" - native 1Password secret reference
func ParsePath(path string, defaultVault string) (*ParsedPath, error) {
	if path == "" {
		return nil, ErrInvalidPath
	}

	// Handle op:// prefix (native 1Password secret reference)
	if strings.HasPrefix(path, "op://") {
		return parseSecretReference(path)
	}

	// Split path into components
	parts := strings.Split(path, "/")

	// Filter out empty parts (handles double slashes)
	var filtered []string
	for _, p := range parts {
		if p != "" {
			filtered = append(filtered, p)
		}
	}
	parts = filtered

	if len(parts) == 0 {
		return nil, ErrInvalidPath
	}

	switch len(parts) {
	case 1:
		// "item" - item only, uses default vault
		if defaultVault == "" {
			return nil, fmt.Errorf("%w: single component path requires default vault", ErrInvalidPath)
		}
		return &ParsedPath{
			Vault: defaultVault,
			Item:  parts[0],
		}, nil

	case 2:
		// Could be "vault/item" or "item/field"
		// If defaultVault is set, treat as "item/field"
		if defaultVault != "" {
			return &ParsedPath{
				Vault: defaultVault,
				Item:  parts[0],
				Field: parts[1],
			}, nil
		}
		// Otherwise treat as "vault/item"
		return &ParsedPath{
			Vault: parts[0],
			Item:  parts[1],
		}, nil

	case 3:
		// "vault/item/field"
		return &ParsedPath{
			Vault: parts[0],
			Item:  parts[1],
			Field: parts[2],
		}, nil

	case 4:
		// "vault/item/section/field"
		return &ParsedPath{
			Vault:   parts[0],
			Item:    parts[1],
			Section: parts[2],
			Field:   parts[3],
		}, nil

	default:
		return nil, fmt.Errorf("%w: too many path components", ErrInvalidPath)
	}
}

// parseSecretReference parses a native 1Password secret reference.
// Format: op://vault/item[/section]/field
func parseSecretReference(ref string) (*ParsedPath, error) {
	// Remove op:// prefix
	ref = strings.TrimPrefix(ref, "op://")

	// Handle query parameters (e.g., ?attribute=totp)
	ref = strings.Split(ref, "?")[0]

	parts := strings.Split(ref, "/")

	// Filter out empty parts
	var filtered []string
	for _, p := range parts {
		if p != "" {
			filtered = append(filtered, p)
		}
	}
	parts = filtered

	switch len(parts) {
	case 2:
		// op://vault/item
		return &ParsedPath{
			Vault: parts[0],
			Item:  parts[1],
		}, nil

	case 3:
		// op://vault/item/field
		return &ParsedPath{
			Vault: parts[0],
			Item:  parts[1],
			Field: parts[2],
		}, nil

	case 4:
		// op://vault/item/section/field
		return &ParsedPath{
			Vault:   parts[0],
			Item:    parts[1],
			Section: parts[2],
			Field:   parts[3],
		}, nil

	default:
		return nil, fmt.Errorf("%w: invalid secret reference format", ErrInvalidPath)
	}
}
