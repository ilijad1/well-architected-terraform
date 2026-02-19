package elb

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossWAFRule checks that application load balancers have a WAFv2 association.
type CrossWAFRule struct{}

func init() {
	engine.RegisterCross(&CrossWAFRule{})
}

func (r *CrossWAFRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ELB-007",
		Name:          "ALB Missing WAF Association",
		Description:   "Application Load Balancers should be associated with a WAFv2 Web ACL to protect against common web exploits.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_lb", "aws_alb", "aws_wafv2_web_acl_association"},
	}
}

func (r *CrossWAFRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	// Collect resource ARNs that have WAF associations
	wafProtected := make(map[string]bool)
	for _, res := range resources {
		if res.Type == "aws_wafv2_web_acl_association" {
			arn, ok := res.GetStringAttr("resource_arn")
			if ok {
				wafProtected[arn] = true
			}
		}
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_lb" && res.Type != "aws_alb" {
			continue
		}

		// Only check application load balancers
		lbType, _ := res.GetStringAttr("load_balancer_type")
		if lbType != "" && lbType != "application" {
			continue
		}

		arn, _ := res.GetStringAttr("arn")
		if !wafProtected[arn] && !wafProtected[res.Address()] {
			findings = append(findings, model.Finding{
				RuleID:      "ELB-007",
				RuleName:    "ALB Missing WAF Association",
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "This Application Load Balancer has no aws_wafv2_web_acl_association. WAF protects against SQL injection, XSS, and other OWASP top 10 threats.",
				Remediation: "Create an aws_wafv2_web_acl_association resource linking a WAFv2 Web ACL to this ALB.",
			})
		}
	}

	return findings
}
