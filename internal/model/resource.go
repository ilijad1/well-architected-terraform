package model

// TerraformResource represents a parsed Terraform resource block.
type TerraformResource struct {
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	File        string                 `json:"file"`
	Line        int                    `json:"line"`
	FullAddress string                 `json:"address,omitempty"`
	Attributes  map[string]interface{} `json:"attributes"`
	Blocks      map[string][]Block     `json:"blocks"`
}

// Block represents a nested block within a Terraform resource.
type Block struct {
	Type       string                 `json:"type"`
	Labels     []string               `json:"labels,omitempty"`
	Attributes map[string]interface{} `json:"attributes"`
	Blocks     map[string][]Block     `json:"blocks"`
}

// Address returns the full resource address (e.g., "aws_s3_bucket.my_bucket").
// If FullAddress is set (e.g., from plan JSON), it is returned instead.
func (r TerraformResource) Address() string {
	if r.FullAddress != "" {
		return r.FullAddress
	}
	return r.Type + "." + r.Name
}

// GetStringAttr returns a string attribute value, or empty string if not found/not a string.
func (r TerraformResource) GetStringAttr(key string) (string, bool) {
	v, ok := r.Attributes[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// GetBoolAttr returns a bool attribute value.
func (r TerraformResource) GetBoolAttr(key string) (bool, bool) {
	v, ok := r.Attributes[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// GetNumberAttr returns a numeric attribute value as float64.
func (r TerraformResource) GetNumberAttr(key string) (float64, bool) {
	v, ok := r.Attributes[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

// HasBlock returns true if the resource has at least one block of the given type.
func (r TerraformResource) HasBlock(blockType string) bool {
	blocks, ok := r.Blocks[blockType]
	return ok && len(blocks) > 0
}

// GetBlocks returns all blocks of the given type.
func (r TerraformResource) GetBlocks(blockType string) []Block {
	return r.Blocks[blockType]
}

// GetStringAttr returns a string attribute value from a block.
func (b Block) GetStringAttr(key string) (string, bool) {
	v, ok := b.Attributes[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// GetBoolAttr returns a bool attribute value from a block.
func (b Block) GetBoolAttr(key string) (bool, bool) {
	v, ok := b.Attributes[key]
	if !ok {
		return false, false
	}
	bv, ok := v.(bool)
	return bv, ok
}
