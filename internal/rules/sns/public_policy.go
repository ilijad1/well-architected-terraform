package sns

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&PublicPolicy{})
}

type PublicPolicy struct{}

func (r *PublicPolicy) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SNS-004",
		Name:          "SNS Topic Policy No Public Access",
		Description:   "SNS topic policies should not allow public access with Principal:*.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_sns_topic_policy"},
	}
}

func (r *PublicPolicy) Evaluate(resource model.TerraformResource) []model.Finding {
	policy, ok := resource.GetStringAttr("policy")
	if !ok {
		return nil
	}
	if strings.Contains(policy, "\"Principal\":\"*\"") || strings.Contains(policy, "\"Principal\": \"*\"") {
		return []model.Finding{{
			RuleID:      "SNS-004",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "SNS topic policy allows public access with Principal:*",
			Remediation: "Restrict the Principal in the topic policy to specific AWS accounts or services",
		}}
	}
	return nil
}
