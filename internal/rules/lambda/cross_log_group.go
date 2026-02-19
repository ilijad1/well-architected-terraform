package lambda

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossLogGroupRule checks that every Lambda function has an explicit
// aws_cloudwatch_log_group for /aws/lambda/{function_name} in the plan.
type CrossLogGroupRule struct{}

func init() {
	engine.RegisterCross(&CrossLogGroupRule{})
}

func (r *CrossLogGroupRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "LAM-008",
		Name:          "Lambda Function Missing Explicit Log Group",
		Description:   "Every Lambda function should have an explicit aws_cloudwatch_log_group for its /aws/lambda/{name} log group to control retention and avoid indefinite log accumulation.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_lambda_function", "aws_cloudwatch_log_group"},
	}
}

func (r *CrossLogGroupRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	// Index CloudWatch log group names
	logGroupNames := make(map[string]bool)
	for _, res := range resources {
		if res.Type == "aws_cloudwatch_log_group" {
			name, ok := res.GetStringAttr("name")
			if ok && name != "" {
				logGroupNames[name] = true
			}
		}
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_lambda_function" {
			continue
		}

		fnName, _ := res.GetStringAttr("function_name")
		if fnName == "" {
			fnName = res.Name
		}

		expectedLogGroup := "/aws/lambda/" + fnName

		if !logGroupNames[expectedLogGroup] {
			findings = append(findings, model.Finding{
				RuleID:      "LAM-008",
				RuleName:    "Lambda Function Missing Explicit Log Group",
				Severity:    model.SeverityMedium,
				Pillar:      model.PillarOperationalExcellence,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "No aws_cloudwatch_log_group with name \"" + expectedLogGroup + "\" found in the plan. Without an explicit log group, Lambda creates one automatically with no retention policy.",
				Remediation: "Add an aws_cloudwatch_log_group resource with name = \"/aws/lambda/" + fnName + "\" and set a retention_in_days value.",
			})
		}
	}

	return findings
}
