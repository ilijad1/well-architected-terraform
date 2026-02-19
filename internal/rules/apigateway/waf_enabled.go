package apigateway

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&WAFEnabled{})
}

// WAFEnabled checks that API Gateway stages have a WAF web ACL associated.
type WAFEnabled struct{}

func (r *WAFEnabled) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "APIGW-005",
		Name:          "API Gateway Stage WAF Enabled",
		Description:   "API Gateway REST API stages should have a WAF web ACL associated to protect against common web exploits.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_api_gateway_stage"},
		DocURL:        "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html",
	}
}

func (r *WAFEnabled) Evaluate(resource model.TerraformResource) []model.Finding {
	webACLARN, ok := resource.GetStringAttr("web_acl_arn")
	if ok && webACLARN != "" {
		return nil
	}
	return []model.Finding{{
		RuleID:      "APIGW-005",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "API Gateway stage does not have a WAF web ACL associated.",
		Remediation: "Set web_acl_arn to the ARN of an aws_wafv2_web_acl to protect the API from common web exploits.",
		DocURL:      r.Metadata().DocURL,
	}}
}
