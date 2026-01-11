# Roadmap: omnivault-onepassword

## Overview

This roadmap outlines the development phases for the omnivault-onepassword provider. The project will be developed iteratively, with each milestone delivering usable functionality.

## Milestones

### Milestone 1: Foundation (v0.1.0)

**Goal**: Basic read-only access to 1Password secrets

**Deliverables**:

- [ ] Project scaffolding
  - [ ] Initialize Go module
  - [ ] Set up golangci-lint configuration
  - [ ] Create GitHub Actions workflows (CI, lint)
  - [ ] Add LICENSE (MIT)
  - [ ] Create basic README.md

- [ ] Core implementation
  - [ ] `Config` struct with service account token support
  - [ ] `Provider` struct implementing `vault.Vault`
  - [ ] `New()` and `NewFromEnv()` constructors
  - [ ] `Name()` and `Capabilities()` methods
  - [ ] `Close()` method

- [ ] Get operation
  - [ ] Path parsing (vault/item/field format)
  - [ ] Support for `op://` prefix passthrough
  - [ ] Field resolution via `Secrets().Resolve()`
  - [ ] Basic error mapping

- [ ] Exists operation
  - [ ] Implement using Get with error check

- [ ] Testing
  - [ ] Unit tests for path parsing
  - [ ] Unit tests for error mapping
  - [ ] Integration test scaffold (skipped without credentials)

**Exit Criteria**:

- Can retrieve a secret using `provider.Get(ctx, "vault/item/field")`
- Returns proper `vault.ErrSecretNotFound` for missing secrets
- 80% test coverage on non-integration code

---

### Milestone 2: Full Item Support (v0.2.0)

**Goal**: Complete item retrieval with multi-field support

**Deliverables**:

- [ ] Enhanced Get operation
  - [ ] Full item retrieval via `Items().Get()`
  - [ ] Vault name to ID resolution
  - [ ] Item name to ID resolution
  - [ ] Multi-field extraction to `secret.Fields`

- [ ] Type conversion
  - [ ] 1Password `Item` to `vault.Secret` conversion
  - [ ] Field type handling (Text, Concealed, URL, Email, Phone)
  - [ ] TOTP code extraction
  - [ ] Metadata population (timestamps, version, IDs)
  - [ ] Tag extraction

- [ ] List operation
  - [ ] List all vaults
  - [ ] List items per vault
  - [ ] Prefix filtering
  - [ ] Path construction (vault/item format)

- [ ] Default vault support
  - [ ] `DefaultVaultID` configuration
  - [ ] `DefaultVaultName` configuration with resolution
  - [ ] Simplified paths when default vault is set

- [ ] Testing
  - [ ] Unit tests for type conversion
  - [ ] Unit tests for list operation
  - [ ] Integration tests for Get and List

**Exit Criteria**:

- Can retrieve full items with all fields
- Can list secrets with prefix filtering
- TOTP codes are computed and accessible

---

### Milestone 3: Write Operations (v0.3.0)

**Goal**: Create, update, and delete secrets

**Deliverables**:

- [ ] Set operation (create)
  - [ ] Create new items via `Items().Create()`
  - [ ] `vault.Secret` to `ItemCreateParams` conversion
  - [ ] Field type inference from names
  - [ ] Configurable default category
  - [ ] Tag creation from metadata

- [ ] Set operation (update)
  - [ ] Detect existing items
  - [ ] Update via `Items().Put()`
  - [ ] Preserve existing fields not in update
  - [ ] Update specific fields only

- [ ] Delete operation
  - [ ] Delete via `Items().Delete()`
  - [ ] Idempotent (no error if not exists)
  - [ ] Handle vault/item not found gracefully

- [ ] Testing
  - [ ] Unit tests for field type inference
  - [ ] Unit tests for secret to item conversion
  - [ ] Integration tests for CRUD lifecycle

**Exit Criteria**:

- Can create new secrets in 1Password
- Can update existing secrets
- Can delete secrets
- Full CRUD lifecycle works end-to-end

---

### Milestone 4: Batch Operations (v0.4.0)

**Goal**: Efficient bulk secret access

**Deliverables**:

- [ ] BatchVault implementation
  - [ ] `GetBatch()` using `Secrets().ResolveAll()`
  - [ ] Partial success handling
  - [ ] Error aggregation

- [ ] Caching layer (optional)
  - [ ] Vault ID cache
  - [ ] Item ID cache
  - [ ] Configurable TTL
  - [ ] Invalidation on write operations

- [ ] Performance optimizations
  - [ ] Parallel vault listing
  - [ ] Connection reuse verification
  - [ ] Rate limit handling

- [ ] Testing
  - [ ] Unit tests for batch operations
  - [ ] Unit tests for cache behavior
  - [ ] Integration tests for batch resolution
  - [ ] Performance benchmarks

**Exit Criteria**:

- `GetBatch()` resolves multiple secrets efficiently
- Caching reduces API calls for repeated lookups
- Performance meets NFR targets

---

### Milestone 5: Production Ready (v1.0.0)

**Goal**: Production-grade quality and documentation

**Deliverables**:

- [ ] Error handling improvements
  - [ ] Comprehensive error type detection
  - [ ] Rate limit backoff
  - [ ] Retry logic for transient failures
  - [ ] Clear, actionable error messages

- [ ] Observability
  - [ ] Structured logging with slog
  - [ ] Debug logging for troubleshooting
  - [ ] Context propagation for tracing

- [ ] Documentation
  - [ ] Complete README with examples
  - [ ] API documentation (godoc)
  - [ ] Troubleshooting guide
  - [ ] Migration guide from direct SDK usage

- [ ] Examples
  - [ ] Basic usage example
  - [ ] OmniVault resolver example
  - [ ] Batch operations example
  - [ ] Multi-provider example

- [ ] Quality assurance
  - [ ] 80%+ test coverage
  - [ ] All linter checks passing
  - [ ] Security review
  - [ ] Performance testing

- [ ] Release
  - [ ] Semantic versioning
  - [ ] CHANGELOG.md
  - [ ] GitHub release with binaries
  - [ ] pkg.go.dev listing

**Exit Criteria**:

- Production-ready quality
- Comprehensive documentation
- All tests passing on CI
- Published to pkg.go.dev

---

## Future Considerations (Post v1.0)

### v1.1: Enhanced Features

- [ ] Secret rotation support (if SDK adds API)
- [ ] Version history access (if SDK adds API)
- [ ] File attachment content retrieval
- [ ] SSH key field handling

### v1.2: Extended Vault Interface

- [ ] Implement `vault.ExtendedVault` interface
- [ ] `GetVersion()` method
- [ ] `ListVersions()` method
- [ ] `Rotate()` method (manual rotation)

### v1.3: Advanced Features

- [ ] Watch for secret changes (polling-based)
- [ ] Automatic token refresh
- [ ] Multiple service account support
- [ ] Vault creation/management

### v2.0: 1Password Connect Support

- [ ] Support for 1Password Connect server
- [ ] Self-hosted deployment option
- [ ] Hybrid cloud/self-hosted configuration

---

## Development Guidelines

### Branching Strategy

- `main` - stable releases
- `develop` - integration branch
- `feature/*` - feature branches
- `fix/*` - bug fix branches

### Release Process

1. Create release branch from `develop`
2. Update version in code
3. Update CHANGELOG.md
4. Create PR to `main`
5. After merge, tag release
6. GitHub Actions publishes release

### Commit Convention

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(get): add multi-field extraction
fix(path): handle empty vault name
docs: update README with examples
test: add integration tests for Set
```

### Pull Request Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Linter passes
- [ ] No breaking changes (or documented)
- [ ] CHANGELOG.md updated

---

## Dependencies and Risks

### External Dependencies

| Dependency | Risk Level | Mitigation |
|------------|------------|------------|
| 1Password SDK | Medium | Pin version, monitor releases |
| omnivault core | Low | Stable interface, same maintainer |

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| SDK breaking changes | Medium | High | Semantic versioning, pin versions |
| Rate limiting | Medium | Medium | Caching, backoff logic |
| WASM compatibility | Low | High | Test on all platforms in CI |
| Go version mismatch | Medium | Medium | Document requirements clearly |

### Resource Requirements

| Phase | Estimated Effort |
|-------|-----------------|
| Milestone 1 | 4-6 hours |
| Milestone 2 | 6-8 hours |
| Milestone 3 | 6-8 hours |
| Milestone 4 | 4-6 hours |
| Milestone 5 | 8-10 hours |
| **Total** | **28-38 hours** |

---

## Success Metrics

### Adoption

- GitHub stars
- pkg.go.dev imports
- Issue/PR activity

### Quality

- Test coverage > 80%
- Zero critical/high severity bugs
- < 1% error rate in production

### Performance

- P50 Get latency < 200ms
- P95 Get latency < 500ms
- P99 Get latency < 1000ms

---

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2025-01-10 | Draft | Initial roadmap created |
