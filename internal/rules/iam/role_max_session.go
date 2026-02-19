package iam

import (
	"fmt"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&RoleMaxSession{})
}

type RoleMaxSession struct{}

func (r *RoleMaxSession) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "IAM-005",
		Name:          "IAM Role Max Session Duration",
		Description:   "IAM roles should have max_session_duration of 3600 seconds (1 hour) or less.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_iam_role"},
	}
}

func (r *RoleMaxSession) Evaluate(resource model.TerraformResource) []model.Finding {
	duration, ok := resource.GetNumberAttr("max_session_duration")
	if !ok || duration <= 3600 {
		return nil
	}

	return []model.Finding{{
		RuleID:      "IAM-005",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: fmt.Sprintf("IAM role max session duration is %.0f seconds, exceeding the recommended 3600 seconds.", duration),
		Remediation: "Set max_session_duration to 3600 (1 hour) or less to limit credential exposure.",
	}}
}
