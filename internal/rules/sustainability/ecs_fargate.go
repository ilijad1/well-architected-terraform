package sustainability

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// ECSFargateRule checks if ECS task definitions support Fargate for serverless compute.
type ECSFargateRule struct{}

func init() {
	engine.Register(&ECSFargateRule{})
}

func (r *ECSFargateRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-011",
		Name:          "ECS Task Not Using Fargate",
		Description:   "ECS task definitions should include FARGATE in requires_compatibilities to enable serverless container execution, which is more energy-efficient than always-on EC2 instances.",
		Severity:      model.SeverityInfo,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_ecs_task_definition"},
	}
}

func (r *ECSFargateRule) Evaluate(resource model.TerraformResource) []model.Finding {
	comps, ok := resource.Attributes["requires_compatibilities"]
	if !ok || comps == nil {
		return []model.Finding{{
			RuleID:      "SUS-011",
			RuleName:    "ECS Task Not Using Fargate",
			Severity:    model.SeverityInfo,
			Pillar:      model.PillarSustainability,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "This ECS task definition does not specify requires_compatibilities. Adding FARGATE enables serverless execution.",
			Remediation: "Add requires_compatibilities = [\"FARGATE\"] to use Fargate serverless compute instead of always-on EC2 instances.",
		}}
	}

	compList, ok := comps.([]interface{})
	if !ok {
		return nil
	}

	for _, c := range compList {
		if s, ok := c.(string); ok && s == "FARGATE" {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "SUS-011",
		RuleName:    "ECS Task Not Using Fargate",
		Severity:    model.SeverityInfo,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This ECS task definition does not include FARGATE in requires_compatibilities. Fargate serverless compute reduces idle resource waste.",
		Remediation: "Add \"FARGATE\" to requires_compatibilities to enable serverless container execution.",
	}}
}
