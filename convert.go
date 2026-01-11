package onepassword

import (
	"fmt"
	"strings"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/agentplexus/omnivault/vault"
)

// itemToSecret converts a 1Password Item to an OmniVault Secret.
func itemToSecret(item op.Item, path string) *vault.Secret {
	secret := &vault.Secret{
		Fields: make(map[string]string),
		Metadata: vault.Metadata{
			Provider: ProviderName,
			Path:     path,
			Version:  fmt.Sprintf("%d", item.Version),
			Extra: map[string]any{
				"vaultId":  item.VaultID,
				"itemId":   item.ID,
				"category": string(item.Category),
			},
		},
	}

	// Convert tags
	if len(item.Tags) > 0 {
		secret.Metadata.Tags = make(map[string]string)
		for _, tag := range item.Tags {
			// Try to parse "key:value" format
			parts := strings.SplitN(tag, ":", 2)
			if len(parts) == 2 {
				secret.Metadata.Tags[parts[0]] = parts[1]
			} else {
				secret.Metadata.Tags[tag] = ""
			}
		}
	}

	// Convert fields
	var firstConcealedValue string
	for _, field := range item.Fields {
		name := field.Title
		if name == "" {
			name = field.ID
		}

		value := field.Value

		// Handle TOTP fields specially - extract computed code
		if field.FieldType == op.ItemFieldTypeTOTP {
			if field.Details != nil {
				if otp := field.Details.OTP(); otp != nil {
					if otp.Code != nil {
						value = *otp.Code
					}
				}
			}
		}

		secret.Fields[name] = value

		// Track first concealed field for primary value
		if firstConcealedValue == "" && field.FieldType == op.ItemFieldTypeConcealed {
			firstConcealedValue = value
		}

		// Set primary value from "password" field
		if strings.ToLower(name) == "password" {
			secret.Value = value
		}
	}

	// Use first concealed field if no "password" field
	if secret.Value == "" && firstConcealedValue != "" {
		secret.Value = firstConcealedValue
	}

	// Fallback to first field value
	if secret.Value == "" && len(secret.Fields) > 0 {
		for _, v := range secret.Fields {
			if v != "" {
				secret.Value = v
				break
			}
		}
	}

	return secret
}

// secretToFields converts an OmniVault Secret to 1Password ItemFields.
func secretToFields(secret *vault.Secret, fieldName string) []op.ItemField {
	var fields []op.ItemField

	// If a specific field name is provided, create a single field
	if fieldName != "" {
		fields = append(fields, op.ItemField{
			ID:        sanitizeID(fieldName),
			Title:     fieldName,
			Value:     secret.Value,
			FieldType: op.ItemFieldTypeConcealed,
		})
		return fields
	}

	// Create fields from secret.Fields
	for name, value := range secret.Fields {
		fieldType := inferFieldType(name, value)
		fields = append(fields, op.ItemField{
			ID:        sanitizeID(name),
			Title:     name,
			Value:     value,
			FieldType: fieldType,
		})
	}

	// If no fields but has a value, create a "password" field
	if len(fields) == 0 && secret.Value != "" {
		fields = append(fields, op.ItemField{
			ID:        "password",
			Title:     "password",
			Value:     secret.Value,
			FieldType: op.ItemFieldTypeConcealed,
		})
	}

	return fields
}

// inferFieldType infers the 1Password field type from the field name and value.
func inferFieldType(name, value string) op.ItemFieldType {
	nameLower := strings.ToLower(name)

	switch {
	case strings.Contains(nameLower, "password") ||
		strings.Contains(nameLower, "secret") ||
		strings.Contains(nameLower, "token") ||
		strings.Contains(nameLower, "key") ||
		strings.Contains(nameLower, "credential"):
		return op.ItemFieldTypeConcealed

	case strings.Contains(nameLower, "url") ||
		strings.Contains(nameLower, "website") ||
		strings.Contains(nameLower, "endpoint"):
		return op.ItemFieldTypeURL

	case strings.Contains(nameLower, "phone") ||
		strings.Contains(nameLower, "mobile") ||
		strings.Contains(nameLower, "tel"):
		return op.ItemFieldTypePhone

	case strings.HasPrefix(value, "otpauth://"):
		return op.ItemFieldTypeTOTP

	default:
		return op.ItemFieldTypeText
	}
}

// sanitizeID creates a valid 1Password field ID from a name.
func sanitizeID(name string) string {
	// Replace spaces and special characters with underscores
	id := strings.ToLower(name)
	id = strings.ReplaceAll(id, " ", "_")
	id = strings.ReplaceAll(id, "-", "_")

	// Remove any remaining special characters
	var result strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			result.WriteRune(r)
		}
	}

	// Trim leading/trailing underscores
	sanitized := strings.Trim(result.String(), "_")

	if sanitized == "" {
		return "field"
	}
	return sanitized
}

// tagsToStrings converts vault.Secret tags to 1Password tag format.
func tagsToStrings(tags map[string]string) []string {
	if len(tags) == 0 {
		return nil
	}

	var result []string
	for k, v := range tags {
		if v != "" {
			result = append(result, fmt.Sprintf("%s:%s", k, v))
		} else {
			result = append(result, k)
		}
	}
	return result
}
