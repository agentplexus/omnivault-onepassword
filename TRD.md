# Technical Requirements Document: omnivault-onepassword

## 1. System Architecture

### 1.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Application                               │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     OmniVault Client                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   Resolver  │  │   Client    │  │   Direct Provider Use   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                  omnivault-onepassword                           │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                      Provider                            │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐  │    │
│  │  │   Get    │  │   Set    │  │  Delete  │  │  List   │  │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └─────────┘  │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   Path Parser                            │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                  Type Converter                          │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                  1Password Go SDK                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ SecretsAPI  │  │  ItemsAPI   │  │      VaultsAPI          │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                   1Password Service                              │
│                  (Cloud Infrastructure)                          │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Component Overview

| Component | Responsibility |
|-----------|----------------|
| Provider | Implements `vault.Vault` interface, orchestrates operations |
| Path Parser | Converts user paths to 1Password secret references |
| Type Converter | Maps between 1Password types and OmniVault types |
| Cache (optional) | Reduces API calls for frequently accessed secrets |

## 2. Detailed Design

### 2.1 Provider Structure

```go
// Provider implements vault.Vault for 1Password.
type Provider struct {
    client *onepassword.Client
    config Config

    // cache stores resolved vault/item IDs to avoid repeated lookups
    cache *pathCache

    mu     sync.RWMutex
    closed bool
}

// Config holds configuration for the 1Password provider.
type Config struct {
    // ServiceAccountToken is the 1Password service account token.
    // Required. Can also be set via OP_SERVICE_ACCOUNT_TOKEN env var.
    ServiceAccountToken string

    // IntegrationName identifies this integration to 1Password.
    // Default: "omnivault-onepassword"
    IntegrationName string

    // IntegrationVersion is the version of this integration.
    // Default: current library version
    IntegrationVersion string

    // DefaultVaultID is used when path doesn't specify a vault.
    // Optional.
    DefaultVaultID string

    // DefaultVaultName is used when path doesn't specify a vault.
    // Resolved to ID on first use. Optional.
    DefaultVaultName string

    // DefaultCategory is the item category for new items.
    // Default: ItemCategorySecureNote
    DefaultCategory onepassword.ItemCategory

    // CacheTTL enables caching of vault/item ID lookups.
    // Zero disables caching. Default: 0 (disabled)
    CacheTTL time.Duration

    // Logger for debug output. Optional.
    Logger *slog.Logger
}
```

### 2.2 Path Format Specification

The provider supports multiple path formats:

```
Format 1: vault/item/field
Format 2: vault/item (returns all fields)
Format 3: item/field (uses DefaultVault)
Format 4: item (uses DefaultVault, returns all fields)
Format 5: op://vault/item/field (native 1Password reference)
```

**Path Parser Implementation:**

```go
// ParsedPath represents a parsed secret path.
type ParsedPath struct {
    Vault   string  // Vault name or ID
    Item    string  // Item name or ID
    Field   string  // Field name (optional)
    Section string  // Section name (optional)
}

// ParsePath parses a path string into components.
func ParsePath(path string, defaultVault string) (*ParsedPath, error) {
    // Handle op:// prefix
    if strings.HasPrefix(path, "op://") {
        return parseSecretReference(path)
    }

    parts := strings.Split(path, "/")
    switch len(parts) {
    case 1:
        // item only
        return &ParsedPath{Vault: defaultVault, Item: parts[0]}, nil
    case 2:
        // Could be vault/item or item/field
        // Heuristic: if defaultVault is set, treat as item/field
        if defaultVault != "" {
            return &ParsedPath{Vault: defaultVault, Item: parts[0], Field: parts[1]}, nil
        }
        return &ParsedPath{Vault: parts[0], Item: parts[1]}, nil
    case 3:
        // vault/item/field
        return &ParsedPath{Vault: parts[0], Item: parts[1], Field: parts[2]}, nil
    case 4:
        // vault/item/section/field
        return &ParsedPath{
            Vault: parts[0], Item: parts[1],
            Section: parts[2], Field: parts[3],
        }, nil
    default:
        return nil, fmt.Errorf("invalid path format: %s", path)
    }
}
```

### 2.3 Interface Implementation

#### 2.3.1 Get Operation

```go
func (p *Provider) Get(ctx context.Context, path string) (*vault.Secret, error) {
    p.mu.RLock()
    defer p.mu.RUnlock()

    if p.closed {
        return nil, vault.NewVaultError("Get", path, p.Name(), vault.ErrClosed)
    }

    parsed, err := ParsePath(path, p.config.DefaultVaultName)
    if err != nil {
        return nil, vault.NewVaultError("Get", path, p.Name(), err)
    }

    // Strategy 1: If field specified, use Secrets().Resolve()
    if parsed.Field != "" {
        return p.resolveField(ctx, parsed)
    }

    // Strategy 2: Get full item using Items().Get()
    return p.getItem(ctx, parsed)
}

func (p *Provider) resolveField(ctx context.Context, parsed *ParsedPath) (*vault.Secret, error) {
    ref := fmt.Sprintf("op://%s/%s/%s", parsed.Vault, parsed.Item, parsed.Field)

    value, err := p.client.Secrets().Resolve(ctx, ref)
    if err != nil {
        return nil, p.mapError("Get", parsed.String(), err)
    }

    return &vault.Secret{
        Value: value,
        Metadata: vault.Metadata{
            Provider: p.Name(),
            Path:     parsed.String(),
        },
    }, nil
}

func (p *Provider) getItem(ctx context.Context, parsed *ParsedPath) (*vault.Secret, error) {
    // Resolve vault name to ID
    vaultID, err := p.resolveVaultID(ctx, parsed.Vault)
    if err != nil {
        return nil, err
    }

    // Resolve item name to ID
    itemID, err := p.resolveItemID(ctx, vaultID, parsed.Item)
    if err != nil {
        return nil, err
    }

    item, err := p.client.Items().Get(ctx, vaultID, itemID)
    if err != nil {
        return nil, p.mapError("Get", parsed.String(), err)
    }

    return p.itemToSecret(item, parsed.String())
}
```

#### 2.3.2 Set Operation

```go
func (p *Provider) Set(ctx context.Context, path string, secret *vault.Secret) error {
    p.mu.Lock()
    defer p.mu.Unlock()

    if p.closed {
        return vault.NewVaultError("Set", path, p.Name(), vault.ErrClosed)
    }

    parsed, err := ParsePath(path, p.config.DefaultVaultName)
    if err != nil {
        return vault.NewVaultError("Set", path, p.Name(), err)
    }

    vaultID, err := p.resolveVaultID(ctx, parsed.Vault)
    if err != nil {
        return err
    }

    // Check if item exists
    itemID, err := p.resolveItemID(ctx, vaultID, parsed.Item)
    if err == nil {
        // Update existing item
        return p.updateItem(ctx, vaultID, itemID, parsed, secret)
    }

    // Create new item
    return p.createItem(ctx, vaultID, parsed, secret)
}

func (p *Provider) createItem(ctx context.Context, vaultID string, parsed *ParsedPath, secret *vault.Secret) error {
    params := onepassword.ItemCreateParams{
        VaultID:  vaultID,
        Title:    parsed.Item,
        Category: p.config.DefaultCategory,
        Fields:   p.secretToFields(secret, parsed.Field),
    }

    // Add tags from metadata
    if secret.Metadata.Tags != nil {
        for k, v := range secret.Metadata.Tags {
            params.Tags = append(params.Tags, fmt.Sprintf("%s:%s", k, v))
        }
    }

    _, err := p.client.Items().Create(ctx, params)
    if err != nil {
        return vault.NewVaultError("Set", parsed.String(), p.Name(), err)
    }

    return nil
}
```

#### 2.3.3 Delete Operation

```go
func (p *Provider) Delete(ctx context.Context, path string) error {
    p.mu.Lock()
    defer p.mu.Unlock()

    if p.closed {
        return vault.NewVaultError("Delete", path, p.Name(), vault.ErrClosed)
    }

    parsed, err := ParsePath(path, p.config.DefaultVaultName)
    if err != nil {
        return vault.NewVaultError("Delete", path, p.Name(), err)
    }

    vaultID, err := p.resolveVaultID(ctx, parsed.Vault)
    if err != nil {
        // Vault not found = nothing to delete
        if errors.Is(err, vault.ErrSecretNotFound) {
            return nil
        }
        return err
    }

    itemID, err := p.resolveItemID(ctx, vaultID, parsed.Item)
    if err != nil {
        // Item not found = nothing to delete
        if errors.Is(err, vault.ErrSecretNotFound) {
            return nil
        }
        return err
    }

    err = p.client.Items().Delete(ctx, vaultID, itemID)
    if err != nil {
        return vault.NewVaultError("Delete", path, p.Name(), err)
    }

    // Invalidate cache
    p.cache.Invalidate(vaultID, itemID)

    return nil
}
```

#### 2.3.4 List Operation

```go
func (p *Provider) List(ctx context.Context, prefix string) ([]string, error) {
    p.mu.RLock()
    defer p.mu.RUnlock()

    if p.closed {
        return nil, vault.NewVaultError("List", prefix, p.Name(), vault.ErrClosed)
    }

    var results []string

    // Get all vaults
    vaults, err := p.client.Vaults().List(ctx)
    if err != nil {
        return nil, vault.NewVaultError("List", prefix, p.Name(), err)
    }

    for _, v := range vaults {
        // Filter by prefix if it specifies a vault
        if prefix != "" && !strings.HasPrefix(v.Title, prefix) && !strings.HasPrefix(prefix, v.Title) {
            continue
        }

        items, err := p.client.Items().List(ctx, v.ID)
        if err != nil {
            continue // Skip vaults we can't access
        }

        for _, item := range items {
            path := fmt.Sprintf("%s/%s", v.Title, item.Title)
            if strings.HasPrefix(path, prefix) {
                results = append(results, path)
            }
        }
    }

    return results, nil
}
```

### 2.4 Type Conversion

#### 2.4.1 1Password Item to vault.Secret

```go
func (p *Provider) itemToSecret(item onepassword.Item, path string) (*vault.Secret, error) {
    secret := &vault.Secret{
        Fields: make(map[string]string),
        Metadata: vault.Metadata{
            Provider:   p.Name(),
            Path:       path,
            Version:    fmt.Sprintf("%d", item.Version),
            CreatedAt:  &vault.Timestamp{Time: item.CreatedAt},
            ModifiedAt: &vault.Timestamp{Time: item.UpdatedAt},
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
            parts := strings.SplitN(tag, ":", 2)
            if len(parts) == 2 {
                secret.Metadata.Tags[parts[0]] = parts[1]
            } else {
                secret.Metadata.Tags[tag] = ""
            }
        }
    }

    // Convert fields
    for _, field := range item.Fields {
        name := field.Title
        if name == "" {
            name = field.ID
        }

        value := field.Value

        // Handle TOTP fields specially
        if field.FieldType == onepassword.ItemFieldTypeTOTP {
            if field.Details != nil && field.Details.OTP() != nil {
                if code := field.Details.OTP().Code; code != nil {
                    value = *code
                }
            }
        }

        secret.Fields[name] = value

        // Set primary value from password or first concealed field
        if secret.Value == "" {
            if field.FieldType == onepassword.ItemFieldTypeConcealed {
                secret.Value = value
            }
        }
    }

    // Use notes as value if no concealed field found
    if secret.Value == "" && item.Notes != "" {
        secret.Value = item.Notes
    }

    // Fallback to first field value
    if secret.Value == "" && len(secret.Fields) > 0 {
        for _, v := range secret.Fields {
            secret.Value = v
            break
        }
    }

    return secret, nil
}
```

#### 2.4.2 vault.Secret to 1Password Fields

```go
func (p *Provider) secretToFields(secret *vault.Secret, fieldName string) []onepassword.ItemField {
    var fields []onepassword.ItemField

    // If specific field requested, create single field
    if fieldName != "" {
        fields = append(fields, onepassword.ItemField{
            ID:        sanitizeID(fieldName),
            Title:     fieldName,
            Value:     secret.Value,
            FieldType: onepassword.ItemFieldTypeConcealed,
        })
        return fields
    }

    // Create fields from secret.Fields
    for name, value := range secret.Fields {
        fieldType := inferFieldType(name, value)
        fields = append(fields, onepassword.ItemField{
            ID:        sanitizeID(name),
            Title:     name,
            Value:     value,
            FieldType: fieldType,
        })
    }

    // If no fields but has value, create a "password" field
    if len(fields) == 0 && secret.Value != "" {
        fields = append(fields, onepassword.ItemField{
            ID:        "password",
            Title:     "password",
            Value:     secret.Value,
            FieldType: onepassword.ItemFieldTypeConcealed,
        })
    }

    return fields
}

func inferFieldType(name, value string) onepassword.ItemFieldType {
    nameLower := strings.ToLower(name)

    switch {
    case strings.Contains(nameLower, "password") ||
         strings.Contains(nameLower, "secret") ||
         strings.Contains(nameLower, "token") ||
         strings.Contains(nameLower, "key"):
        return onepassword.ItemFieldTypeConcealed
    case strings.Contains(nameLower, "url") ||
         strings.Contains(nameLower, "website"):
        return onepassword.ItemFieldTypeURL
    case strings.Contains(nameLower, "email"):
        return onepassword.ItemFieldTypeEmail
    case strings.Contains(nameLower, "phone"):
        return onepassword.ItemFieldTypePhone
    case strings.HasPrefix(value, "otpauth://"):
        return onepassword.ItemFieldTypeTOTP
    default:
        return onepassword.ItemFieldTypeText
    }
}
```

### 2.5 Error Handling

```go
func (p *Provider) mapError(op, path string, err error) error {
    if err == nil {
        return nil
    }

    errStr := err.Error()

    // Check for specific error types
    var rateLimitErr *onepassword.RateLimitExceededError
    if errors.As(err, &rateLimitErr) {
        return vault.NewVaultError(op, path, p.Name(), vault.ErrRateLimited)
    }

    // String-based error detection (SDK limitation)
    switch {
    case strings.Contains(errStr, "itemNotFound"),
         strings.Contains(errStr, "vaultNotFound"),
         strings.Contains(errStr, "fieldNotFound"):
        return vault.NewVaultError(op, path, p.Name(), vault.ErrSecretNotFound)

    case strings.Contains(errStr, "unauthorized"),
         strings.Contains(errStr, "forbidden"),
         strings.Contains(errStr, "access denied"):
        return vault.NewVaultError(op, path, p.Name(), vault.ErrAccessDenied)

    case strings.Contains(errStr, "invalid service account token"):
        return vault.NewVaultError(op, path, p.Name(),
            fmt.Errorf("%w: invalid service account token", vault.ErrAccessDenied))
    }

    return vault.NewVaultError(op, path, p.Name(), err)
}
```

### 2.6 Caching (Optional)

```go
type pathCache struct {
    mu      sync.RWMutex
    vaults  map[string]string        // name -> ID
    items   map[string]string        // vaultID/name -> itemID
    ttl     time.Duration
    expires map[string]time.Time
}

func (c *pathCache) GetVaultID(name string) (string, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()

    if id, ok := c.vaults[name]; ok {
        if time.Now().Before(c.expires["vault:"+name]) {
            return id, true
        }
    }
    return "", false
}

func (c *pathCache) SetVaultID(name, id string) {
    c.mu.Lock()
    defer c.mu.Unlock()

    c.vaults[name] = id
    c.expires["vault:"+name] = time.Now().Add(c.ttl)
}
```

## 3. API Reference

### 3.1 Public API

```go
package onepassword

// New creates a new 1Password provider.
func New(config Config) (*Provider, error)

// NewFromEnv creates a provider using OP_SERVICE_ACCOUNT_TOKEN.
func NewFromEnv() (*Provider, error)

// Provider implements vault.Vault for 1Password.
type Provider struct { /* ... */ }

func (p *Provider) Get(ctx context.Context, path string) (*vault.Secret, error)
func (p *Provider) Set(ctx context.Context, path string, secret *vault.Secret) error
func (p *Provider) Delete(ctx context.Context, path string) error
func (p *Provider) Exists(ctx context.Context, path string) (bool, error)
func (p *Provider) List(ctx context.Context, prefix string) ([]string, error)
func (p *Provider) Name() string
func (p *Provider) Capabilities() vault.Capabilities
func (p *Provider) Close() error

// GetBatch implements vault.BatchVault for bulk secret retrieval.
func (p *Provider) GetBatch(ctx context.Context, paths []string) (map[string]*vault.Secret, error)

// Config holds provider configuration.
type Config struct {
    ServiceAccountToken string
    IntegrationName     string
    IntegrationVersion  string
    DefaultVaultID      string
    DefaultVaultName    string
    DefaultCategory     onepassword.ItemCategory
    CacheTTL            time.Duration
    Logger              *slog.Logger
}

// ParsedPath represents a parsed 1Password path.
type ParsedPath struct {
    Vault   string
    Item    string
    Field   string
    Section string
}

func ParsePath(path, defaultVault string) (*ParsedPath, error)
```

### 3.2 Constants

```go
const (
    // ProviderName is the name returned by Provider.Name()
    ProviderName = "onepassword"

    // EnvServiceAccountToken is the environment variable for the token
    EnvServiceAccountToken = "OP_SERVICE_ACCOUNT_TOKEN"

    // DefaultIntegrationName is used if not specified
    DefaultIntegrationName = "omnivault-onepassword"
)

// Common item categories
const (
    CategoryLogin          = onepassword.ItemCategoryLogin
    CategorySecureNote     = onepassword.ItemCategorySecureNote
    CategoryAPICredentials = onepassword.ItemCategoryAPICredentials
    CategoryDatabase       = onepassword.ItemCategoryDatabase
    CategoryServer         = onepassword.ItemCategoryServer
)
```

## 4. Testing Strategy

### 4.1 Unit Tests

```go
// path_test.go
func TestParsePath(t *testing.T) {
    tests := []struct {
        input        string
        defaultVault string
        want         *ParsedPath
        wantErr      bool
    }{
        {"vault/item/field", "", &ParsedPath{Vault: "vault", Item: "item", Field: "field"}, false},
        {"vault/item", "", &ParsedPath{Vault: "vault", Item: "item"}, false},
        {"item/field", "default", &ParsedPath{Vault: "default", Item: "item", Field: "field"}, false},
        {"op://vault/item/field", "", &ParsedPath{Vault: "vault", Item: "item", Field: "field"}, false},
        {"", "", nil, true},
    }
    // ...
}

// convert_test.go
func TestInferFieldType(t *testing.T) {
    tests := []struct {
        name  string
        value string
        want  onepassword.ItemFieldType
    }{
        {"password", "secret", onepassword.ItemFieldTypeConcealed},
        {"api_key", "key123", onepassword.ItemFieldTypeConcealed},
        {"website", "https://example.com", onepassword.ItemFieldTypeURL},
        {"email", "user@example.com", onepassword.ItemFieldTypeEmail},
        {"notes", "some text", onepassword.ItemFieldTypeText},
    }
    // ...
}
```

### 4.2 Integration Tests

```go
// integration_test.go
// +build integration

func TestProviderIntegration(t *testing.T) {
    token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
    if token == "" {
        t.Skip("OP_SERVICE_ACCOUNT_TOKEN not set")
    }

    vaultID := os.Getenv("OP_TEST_VAULT_ID")
    if vaultID == "" {
        t.Skip("OP_TEST_VAULT_ID not set")
    }

    provider, err := New(Config{
        ServiceAccountToken: token,
        DefaultVaultID:      vaultID,
    })
    require.NoError(t, err)
    defer provider.Close()

    ctx := context.Background()

    t.Run("CRUD operations", func(t *testing.T) {
        path := fmt.Sprintf("test-item-%d", time.Now().Unix())

        // Create
        err := provider.Set(ctx, path, &vault.Secret{Value: "test-value"})
        require.NoError(t, err)

        // Read
        secret, err := provider.Get(ctx, path)
        require.NoError(t, err)
        assert.Equal(t, "test-value", secret.Value)

        // Update
        err = provider.Set(ctx, path, &vault.Secret{Value: "updated-value"})
        require.NoError(t, err)

        secret, err = provider.Get(ctx, path)
        require.NoError(t, err)
        assert.Equal(t, "updated-value", secret.Value)

        // Delete
        err = provider.Delete(ctx, path)
        require.NoError(t, err)

        // Verify deleted
        _, err = provider.Get(ctx, path)
        assert.ErrorIs(t, err, vault.ErrSecretNotFound)
    })
}
```

### 4.3 Mock Testing

```go
// mock_test.go
type mockSecretsAPI struct {
    resolveFunc func(ctx context.Context, ref string) (string, error)
}

func (m *mockSecretsAPI) Resolve(ctx context.Context, ref string) (string, error) {
    return m.resolveFunc(ctx, ref)
}

func TestGetWithMock(t *testing.T) {
    mock := &mockSecretsAPI{
        resolveFunc: func(ctx context.Context, ref string) (string, error) {
            if ref == "op://vault/item/field" {
                return "secret-value", nil
            }
            return "", errors.New("not found")
        },
    }

    // Test with mock...
}
```

## 5. File Structure

```
omnivault-onepassword/
├── onepassword.go           # Provider implementation
├── onepassword_test.go      # Unit tests
├── config.go                # Configuration types
├── path.go                  # Path parsing
├── path_test.go             # Path parsing tests
├── convert.go               # Type conversions
├── convert_test.go          # Conversion tests
├── errors.go                # Error mapping
├── cache.go                 # Optional caching
├── batch.go                 # BatchVault implementation
├── integration_test.go      # Integration tests (build tag)
├── examples/
│   ├── basic/main.go        # Basic usage example
│   ├── resolver/main.go     # With OmniVault resolver
│   └── batch/main.go        # Batch operations
├── go.mod
├── go.sum
├── README.md
├── PRD.md
├── TRD.md
├── ROADMAP.md
├── LICENSE
├── .golangci.yaml
└── .github/
    └── workflows/
        ├── ci.yaml
        ├── lint.yaml
        └── release.yaml
```

## 6. Dependencies

### 6.1 Direct Dependencies

```go
require (
    github.com/agentplexus/omnivault v0.1.0
    github.com/1password/onepassword-sdk-go v0.1.3
)
```

### 6.2 Development Dependencies

```go
require (
    github.com/stretchr/testify v1.9.0
)
```

### 6.3 Go Version

- Minimum: Go 1.22 (omnivault compatibility)
- Recommended: Go 1.24+ (1Password SDK requirement)

## 7. Security Considerations

### 7.1 Token Handling

- Never log the service account token
- Clear token from memory after client initialization
- Support token rotation without restart (future)

### 7.2 Secret Handling

- Never log secret values at any log level
- Use `[REDACTED]` for debug output
- Clear secret values from memory when possible

### 7.3 Error Messages

- Don't leak sensitive paths in error messages
- Sanitize user input in error output

## 8. Performance Considerations

### 8.1 Caching Strategy

- Cache vault name -> ID mappings (they rarely change)
- Cache item name -> ID mappings with short TTL
- Invalidate cache on Set/Delete operations

### 8.2 Batch Operations

- Use `ResolveAll()` for multiple field lookups
- Parallelize vault listing when possible
- Limit concurrent API calls to avoid rate limiting

### 8.3 Connection Management

- Reuse the 1Password client instance
- The SDK handles connection pooling internally
