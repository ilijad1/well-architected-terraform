package parser

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// planJSON represents the top-level structure of `terraform show -json plan.bin`.
type planJSON struct {
	PlannedValues   *plannedValues   `json:"planned_values"`
	ResourceChanges []resourceChange `json:"resource_changes"`
}

// resourceChange describes the planned action for a resource.
type resourceChange struct {
	Address string       `json:"address"`
	Change  changeDetail `json:"change"`
}

// changeDetail holds the list of actions for a resource change.
// Common values: ["create"], ["update"], ["delete"], ["no-op"], ["create", "delete"].
type changeDetail struct {
	Actions []string `json:"actions"`
}

type plannedValues struct {
	RootModule *planModule `json:"root_module"`
}

type planModule struct {
	Resources    []planResource `json:"resources"`
	ChildModules []planModule   `json:"child_modules"`
}

type planResource struct {
	Address string                 `json:"address"`
	Mode    string                 `json:"mode"`
	Type    string                 `json:"type"`
	Name    string                 `json:"name"`
	Values  map[string]interface{} `json:"values"`
}

// ParsePlanFile parses a Terraform plan JSON file and returns resources.
func ParsePlanFile(path string) ([]model.TerraformResource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading plan file: %w", err)
	}

	var plan planJSON
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("parsing plan JSON: %w", err)
	}

	if plan.PlannedValues == nil || plan.PlannedValues.RootModule == nil {
		return nil, nil
	}

	// Build a set of resource addresses whose only planned action is "delete".
	// These resources are being destroyed and should not be analyzed.
	destroyOnly := buildDestroySet(plan.ResourceChanges)

	var resources []model.TerraformResource
	collectResources(plan.PlannedValues.RootModule, destroyOnly, &resources)
	return resources, nil
}

// buildDestroySet returns a set of addresses where the only planned action is "delete".
func buildDestroySet(changes []resourceChange) map[string]bool {
	set := make(map[string]bool, len(changes))
	for _, c := range changes {
		if len(c.Change.Actions) == 1 && c.Change.Actions[0] == "delete" {
			set[c.Address] = true
		}
	}
	return set
}

// collectResources walks the module tree depth-first, collecting all resources.
// Resources whose address appears in destroyOnly are skipped.
func collectResources(mod *planModule, destroyOnly map[string]bool, out *[]model.TerraformResource) {
	for _, r := range mod.Resources {
		if destroyOnly[r.Address] {
			continue
		}
		*out = append(*out, convertPlanResource(r))
	}
	for i := range mod.ChildModules {
		collectResources(&mod.ChildModules[i], destroyOnly, out)
	}
}

// convertPlanResource converts a plan JSON resource to a TerraformResource.
func convertPlanResource(r planResource) model.TerraformResource {
	resType := r.Type
	if r.Mode == "data" {
		resType = "data." + r.Type
	}

	attrs := make(map[string]interface{})
	blocks := make(map[string][]model.Block)

	for key, val := range r.Values {
		// Skip null values: these represent "(known after apply)" attributes in the plan.
		// Rules must treat a missing attribute as "not configured", not as a misconfiguration.
		if val == nil {
			continue
		}
		if isBlockValue(val) {
			blocks[key] = convertBlocks(key, val.([]interface{}))
		} else {
			attrs[key] = val
		}
	}

	return model.TerraformResource{
		Type:        resType,
		Name:        r.Name,
		File:        "tfplan",
		Line:        0,
		FullAddress: r.Address,
		Attributes:  attrs,
		Blocks:      blocks,
	}
}

// isBlockValue returns true if the value looks like a Terraform block:
// a []interface{} where elements are map[string]interface{}.
func isBlockValue(v interface{}) bool {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return false
	}
	_, ok = arr[0].(map[string]interface{})
	return ok
}

// convertBlocks converts an array of maps into model.Block slices.
func convertBlocks(blockType string, items []interface{}) []model.Block {
	var blocks []model.Block
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		attrs := make(map[string]interface{})
		nested := make(map[string][]model.Block)

		for key, val := range m {
			if isBlockValue(val) {
				nested[key] = convertBlocks(key, val.([]interface{}))
			} else {
				attrs[key] = val
			}
		}

		blocks = append(blocks, model.Block{
			Type:       blockType,
			Attributes: attrs,
			Blocks:     nested,
		})
	}
	return blocks
}
