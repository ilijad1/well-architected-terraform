# Contributing to well-architected-terraform

Thank you for your interest in contributing. This document covers everything you need to add rules, fix bugs, or improve the tool.

## Table of Contents

- [Getting Started](#getting-started)
- [Adding a New Rule](#adding-a-new-rule)
- [Adding a New AWS Service](#adding-a-new-aws-service)
- [Testing](#testing)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Code Conventions](#code-conventions)

---

## Getting Started

```bash
git clone https://github.com/ilijad1/well-architected-terraform
cd well-architected-terraform
make build   # produces ./wat
make test    # run all tests
```

Requirements: Go 1.21+

---

## Adding a New Rule

Rules are the primary contribution path. Each rule lives in its own file inside `internal/rules/<service>/`.

### 1. Determine the rule type

**Single-resource rule** — checks one resource at a time (e.g., "S3 bucket must have versioning enabled"):

```go
// internal/rules/s3/my_rule.go
package s3

import (
    "github.com/ilijad1/well-architected-terraform/internal/engine"
    "github.com/ilijad1/well-architected-terraform/internal/model"
)

type MyRule struct{}

func init() { engine.Register(&MyRule{}) }

func (r *MyRule) Metadata() model.RuleMetadata {
    return model.RuleMetadata{
        ID:            "S3-013",
        Name:          "S3 Bucket Missing Something",
        Description:   "Full description for the rule list.",
        Severity:      model.SeverityHigh,
        Pillar:        model.PillarSecurity,
        ResourceTypes: []string{"aws_s3_bucket"},
    }
}

func (r *MyRule) Evaluate(res model.TerraformResource) []model.Finding {
    // return nil = no finding (pass)
    // return []model.Finding{{...}} = finding (fail)
}
```

**Cross-resource rule** — correlates across all resources (e.g., "every bucket must have a companion public access block resource"):

```go
type MyCrossRule struct{}

func init() { engine.RegisterCross(&MyCrossRule{}) }

func (r *MyCrossRule) Metadata() model.RuleMetadata { ... }
func (r *MyCrossRule) EvaluateAll(resources []model.TerraformResource) []model.Finding { ... }
```

### 2. Choose a rule ID

Check existing IDs to find the next available number:

```bash
./wat list-rules | grep "^S3-"   # find next S3 rule number
```

Rule ID format: `SERVICE-NNN` (e.g., `S3-013`, `EC2-012`, `SUS-018`).

### 3. Avoid problematic filenames

Go treats filenames ending in OS or architecture identifiers as build constraints. Avoid names like `rule_linux.go`, `rule_arm64.go`, `rule_amd64.go`. Use descriptive names instead: `encryption_at_rest.go`, `cross_logging.go`.

### 4. Write tests

Add tests to the existing `internal/rules/<service>/<service>_test.go` file. Use struct construction directly — not testdata files:

```go
func TestMyRule_Pass(t *testing.T) {
    r := &MyRule{}
    findings := r.Evaluate(model.TerraformResource{
        Type:       "aws_s3_bucket",
        Name:       "test",
        Attributes: map[string]interface{}{"versioning": true},
        Blocks:     map[string][]model.Block{},
    })
    assert.Empty(t, findings)
}

func TestMyRule_Fail(t *testing.T) {
    r := &MyRule{}
    findings := r.Evaluate(model.TerraformResource{
        Type:       "aws_s3_bucket",
        Name:       "test",
        Attributes: map[string]interface{}{},
        Blocks:     map[string][]model.Block{},
    })
    assert.Len(t, findings, 1)
    assert.Equal(t, "S3-013", findings[0].RuleID)
}
```

Minimum test cases:
- **Single-resource**: at least one pass + one fail
- **Cross-resource**: no companion (fail), with companion (pass), multiple resources with one uncovered (1 finding), no primary resources (0 findings)

---

## Adding a New AWS Service

If no package exists for your service:

1. Create `internal/rules/<service>/` directory
2. Add a blank import to `internal/rules/register.go`:

```go
_ "github.com/ilijad1/well-architected-terraform/internal/rules/myservice"
```

3. Choose a package name that doesn't conflict with Go standard library or the `config` package (use `awsconfig` instead of `config`, for example)

---

## Testing

```bash
make test          # all tests, verbose
make test-short    # all tests, quiet
make lint          # go vet
```

All tests must pass before a PR can be merged. Run with the race detector locally before submitting:

```bash
go test -race ./...
```

---

## Submitting a Pull Request

1. Fork the repo and create a branch: `git checkout -b add-ec2-rule`
2. Make your changes with tests
3. Verify: `make build && make test && make lint`
4. Open a PR with a clear description:
   - What rule(s) does this add or fix?
   - Which pillar and severity?
   - What Terraform resource type(s) does it check?
   - Link to the relevant Well-Architected guidance if applicable

---

## Code Conventions

- One file per rule, one `_test.go` per service package
- Pillar constants: `model.PillarSecurity`, `model.PillarReliability`, `model.PillarOperationalExcellence`, `model.PillarPerformanceEfficiency`, `model.PillarCostOptimization`, `model.PillarSustainability`
- Severity constants: `model.SeverityCritical`, `model.SeverityHigh`, `model.SeverityMedium`, `model.SeverityLow`, `model.SeverityInfo`
- `Block` type has `GetStringAttr` and `GetBoolAttr` but no `GetNumberAttr` — access `block.Attributes["key"]` directly for numbers
- Finding `Description` explains what is wrong; `Remediation` explains how to fix it
- No global mutable state in rules — rule structs should be stateless

## Questions?

Open a GitHub Discussion or file an issue with the `question` label.
