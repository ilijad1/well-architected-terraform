// Package route53 contains Well-Architected rules for AWS ROUTE53 resources.
package route53

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&QueryLogging{})
	engine.Register(&DNSSEC{})
}

type QueryLogging struct{}

func (r *QueryLogging) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "R53-001", Name: "Route53 Query Logging", Description: "Route53 query logs should have a CloudWatch log group configured.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_route53_query_log"}}
}

func (r *QueryLogging) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetStringAttr("cloudwatch_log_group_arn"); ok && v != "" {
		return nil
	}
	return []model.Finding{{RuleID: "R53-001", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Route53 query log does not have a CloudWatch log group configured.", Remediation: "Set cloudwatch_log_group_arn to a valid CloudWatch log group ARN."}}
}

type DNSSEC struct{}

func (r *DNSSEC) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "R53-002", Name: "Route53 DNSSEC Signing", Description: "Route53 hosted zones should have DNSSEC signing enabled.", Severity: model.SeverityLow, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_route53_hosted_zone_dnssec"}}
}

func (r *DNSSEC) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetStringAttr("signing_status"); ok && v == "SIGNING" {
		return nil
	}
	return []model.Finding{{RuleID: "R53-002", RuleName: r.Metadata().Name, Severity: model.SeverityLow, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Route53 hosted zone does not have DNSSEC signing enabled.", Remediation: "Set signing_status = \"SIGNING\" to enable DNSSEC."}}
}
