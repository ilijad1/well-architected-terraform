package cloudtrail

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossLogGroupRule checks that every CloudTrail trail has a corresponding
// aws_cloudwatch_log_group defined in the plan.
type CrossLogGroupRule struct{}

func init() {
	engine.RegisterCross(&CrossLogGroupRule{})
}

func (r *CrossLogGroupRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CT-007",
		Name:          "CloudTrail Missing CloudWatch Log Group",
		Description:   "CloudTrail should reference an aws_cloudwatch_log_group that is defined in the same Terraform plan for traceability and retention control.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_cloudtrail", "aws_cloudwatch_log_group"},
	}
}

func (r *CrossLogGroupRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	logGroupNames := make(map[string]bool)
	for _, res := range resources {
		if res.Type == "aws_cloudwatch_log_group" {
			name, ok := res.GetStringAttr("name")
			if ok && name != "" {
				logGroupNames[name] = true
			}
			logGroupNames[res.Name] = true
			logGroupNames[res.Address()] = true
		}
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_cloudtrail" {
			continue
		}

		arn, hasARN := res.GetStringAttr("cloud_watch_logs_group_arn")
		if !hasARN || arn == "" {
			// No log group configured at all — CT-004 already flags this as an attribute issue;
			// CT-007 flags that no log group resource exists in the plan.
			if len(logGroupNames) == 0 {
				findings = append(findings, model.Finding{
					RuleID:      "CT-007",
					RuleName:    "CloudTrail Missing CloudWatch Log Group",
					Severity:    model.SeverityHigh,
					Pillar:      model.PillarOperationalExcellence,
					Resource:    res.Address(),
					File:        res.File,
					Line:        res.Line,
					Description: "This CloudTrail has no CloudWatch log group configured and no aws_cloudwatch_log_group resource exists in the plan.",
					Remediation: "Add an aws_cloudwatch_log_group resource and reference it in the CloudTrail's cloud_watch_logs_group_arn attribute.",
				})
			}
			continue
		}

		// Check if the ARN references a log group that exists in the plan.
		found := false
		for groupName := range logGroupNames {
			if strings.Contains(arn, groupName) {
				found = true
				break
			}
		}

		if !found {
			findings = append(findings, model.Finding{
				RuleID:      "CT-007",
				RuleName:    "CloudTrail Missing CloudWatch Log Group",
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarOperationalExcellence,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "This CloudTrail references a CloudWatch log group ARN but no matching aws_cloudwatch_log_group resource was found in the plan.",
				Remediation: "Add an aws_cloudwatch_log_group resource whose name matches the log group referenced in cloud_watch_logs_group_arn.",
			})
		}
	}

	return findings
}
