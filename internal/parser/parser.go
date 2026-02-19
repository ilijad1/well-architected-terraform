package parser

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// Parser reads Terraform HCL files and extracts resource definitions.
type Parser struct{}

// New creates a new Parser.
func New() *Parser {
	return &Parser{}
}

// ParseDirectory walks a directory and parses all .tf files.
func (p *Parser) ParseDirectory(dir string) ([]model.TerraformResource, error) {
	var resources []model.TerraformResource

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".terraform" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".tf" {
			return nil
		}

		fileResources, parseErr := p.ParseFile(path)
		if parseErr != nil {
			return fmt.Errorf("parsing %s: %w", path, parseErr)
		}
		resources = append(resources, fileResources...)
		return nil
	})

	return resources, err
}

// ParseFile parses a single .tf file and extracts resource blocks.
func (p *Parser) ParseFile(path string) ([]model.TerraformResource, error) {
	src, err := os.ReadFile(path) // #nosec G304 -- path is a CLI argument supplied by the operator
	if err != nil {
		return nil, err
	}

	file, diags := hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("HCL parse error: %s", diags.Error())
	}

	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("unexpected body type in %s", path)
	}

	var resources []model.TerraformResource

	for _, block := range body.Blocks {
		if len(block.Labels) < 2 {
			continue
		}
		if block.Type != "resource" && block.Type != "data" {
			continue
		}

		resourceType := block.Labels[0]
		if block.Type == "data" {
			resourceType = "data." + resourceType
		}

		res := model.TerraformResource{
			Type:       resourceType,
			Name:       block.Labels[1],
			File:       path,
			Line:       block.DefRange().Start.Line,
			Attributes: extractAttributes(block.Body),
			Blocks:     extractBlocks(block.Body),
		}
		resources = append(resources, res)
	}

	return resources, nil
}

// extractAttributes extracts literal attribute values from an HCL body.
// Dynamic expressions (variable references, function calls, etc.) are stored as string representations.
func extractAttributes(body *hclsyntax.Body) map[string]interface{} {
	attrs := make(map[string]interface{})

	for name, attr := range body.Attributes {
		val, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			// Expression couldn't be evaluated (likely references a variable).
			// Store the source expression as a string for informational purposes.
			attrs[name] = expressionToString(attr.Expr)
			continue
		}
		attrs[name] = ctyToGo(val)
	}

	return attrs
}

// extractBlocks extracts nested blocks from an HCL body.
func extractBlocks(body *hclsyntax.Body) map[string][]model.Block {
	blocks := make(map[string][]model.Block)

	for _, block := range body.Blocks {
		b := model.Block{
			Type:       block.Type,
			Labels:     block.Labels,
			Attributes: extractAttributes(block.Body),
			Blocks:     extractBlocks(block.Body),
		}
		blocks[block.Type] = append(blocks[block.Type], b)
	}

	return blocks
}

// ctyToGo converts a cty.Value to a native Go value.
func ctyToGo(val cty.Value) interface{} {
	if val.IsNull() {
		return nil
	}

	ty := val.Type()

	switch {
	case ty == cty.String:
		return val.AsString()
	case ty == cty.Bool:
		return val.True()
	case ty == cty.Number:
		bf := val.AsBigFloat()
		f, _ := bf.Float64()
		return f
	case ty.IsListType() || ty.IsTupleType() || ty.IsSetType():
		var result []interface{}
		for it := val.ElementIterator(); it.Next(); {
			_, v := it.Element()
			result = append(result, ctyToGo(v))
		}
		return result
	case ty.IsMapType() || ty.IsObjectType():
		result := make(map[string]interface{})
		for it := val.ElementIterator(); it.Next(); {
			k, v := it.Element()
			result[k.AsString()] = ctyToGo(v)
		}
		return result
	default:
		return val.GoString()
	}
}

// expressionToString extracts the source text of an HCL expression.
func expressionToString(expr hclsyntax.Expression) string {
	rng := expr.Range()
	return fmt.Sprintf("${%s}", rng.SliceBytes(nil))
}
