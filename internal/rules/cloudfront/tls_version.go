package cloudfront

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&TLSVersionRule{})
}

type TLSVersionRule struct{}

func (r *TLSVersionRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CF-001",
		Name:          "CloudFront TLS Version",
		Description:   "CloudFront distributions should use TLS 1.2 or higher",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_cloudfront_distribution"},
		DocURL:        "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html",
	}
}

func (r *TLSVersionRule) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("viewer_certificate") {
		findings = append(findings, model.Finding{
			RuleID:      "CF-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "CloudFront distribution does not have a viewer_certificate block configured",
			Remediation: "Add viewer_certificate block with minimum_protocol_version set to TLSv1.2_2021 or higher",
		})
		return findings
	}

	blocks := resource.GetBlocks("viewer_certificate")
	if len(blocks) > 0 {
		viewerCert := blocks[0]
		minProtocol, exists := viewerCert.GetStringAttr("minimum_protocol_version")
		if !exists || !strings.Contains(minProtocol, "TLSv1.2") {
			findings = append(findings, model.Finding{
				RuleID:      "CF-001",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: "CloudFront distribution does not use TLS 1.2 or higher",
				Remediation: "Set minimum_protocol_version to TLSv1.2_2021 or higher in viewer_certificate block",
			})
		}
	}

	return findings
}
