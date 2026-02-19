package elb

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&HTTPSListenerRule{})
}

type HTTPSListenerRule struct{}

func (r *HTTPSListenerRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ELB-004",
		Name:          "Load Balancer HTTPS Listener",
		Description:   "Load Balancer listeners should use HTTPS or TLS protocol",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_lb_listener"},
		DocURL:        "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html",
	}
}

func (r *HTTPSListenerRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	protocol, exists := resource.GetStringAttr("protocol")
	if !exists || protocol == "HTTP" {
		findings = append(findings, model.Finding{
			RuleID:      "ELB-004",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "Load balancer listener uses unencrypted HTTP protocol",
			Remediation: "Set protocol to 'HTTPS' or 'TLS' to encrypt traffic in transit",
		})
	}

	return findings
}
