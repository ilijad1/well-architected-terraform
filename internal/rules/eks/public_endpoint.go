package eks

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&PublicEndpoint{})
}

type PublicEndpoint struct{}

func (r *PublicEndpoint) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EKS-004",
		Name:          "EKS Public Endpoint Restriction",
		Description:   "Ensures EKS cluster public endpoint access is restricted",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_eks_cluster"},
		DocURL:        "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html",
	}
}

func (r *PublicEndpoint) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("vpc_config") {
		findings = append(findings, model.Finding{
			RuleID:      "EKS-004",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "EKS cluster does not have vpc_config block configured",
			Remediation: "Add a vpc_config block and either disable public access or restrict public_access_cidrs to specific IP ranges",
			DocURL:      r.Metadata().DocURL,
		})
		return findings
	}

	vpcConfigBlocks := resource.GetBlocks("vpc_config")

	for _, block := range vpcConfigBlocks {
		publicAccess, publicAccessExists := block.GetBoolAttr("endpoint_public_access")

		// If public access is explicitly disabled, this is compliant
		if publicAccessExists && !publicAccess {
			continue
		}

		// If public access is true or not set (defaults to true), check CIDR restrictions
		if !publicAccessExists || publicAccess {
			cidrs, cidrsExist := block.Attributes["public_access_cidrs"].([]interface{})

			// Check if CIDRs are unrestricted (0.0.0.0/0)
			isUnrestricted := false

			if !cidrsExist || len(cidrs) == 0 {
				// No CIDR restriction specified, defaults to 0.0.0.0/0
				isUnrestricted = true
			} else {
				for _, cidr := range cidrs {
					if cidrStr, ok := cidr.(string); ok && cidrStr == "0.0.0.0/0" {
						isUnrestricted = true
						break
					}
				}
			}

			if isUnrestricted {
				findings = append(findings, model.Finding{
					RuleID:      "EKS-004",
					RuleName:    r.Metadata().Name,
					Severity:    model.SeverityHigh,
					Pillar:      model.PillarSecurity,
					Resource:    resource.Address(),
					File:        resource.File,
					Line:        resource.Line,
					Description: "EKS cluster has unrestricted public endpoint access (0.0.0.0/0)",
					Remediation: "Either set endpoint_public_access to false, or restrict public_access_cidrs to specific trusted IP ranges instead of 0.0.0.0/0",
					DocURL:      r.Metadata().DocURL,
				})
			}
		}
	}

	return findings
}
