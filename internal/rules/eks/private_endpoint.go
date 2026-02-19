package eks

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&PrivateEndpoint{})
}

type PrivateEndpoint struct{}

func (r *PrivateEndpoint) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EKS-003",
		Name:          "EKS Private Endpoint Access",
		Description:   "Ensures EKS clusters have private endpoint access enabled",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_eks_cluster"},
		DocURL:        "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html",
	}
}

func (r *PrivateEndpoint) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("vpc_config") {
		findings = append(findings, model.Finding{
			RuleID:      "EKS-003",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "EKS cluster does not have vpc_config block configured",
			Remediation: "Add a vpc_config block with endpoint_private_access set to true to enable private API server endpoint access",
			DocURL:      r.Metadata().DocURL,
		})
		return findings
	}

	vpcConfigBlocks := resource.GetBlocks("vpc_config")
	hasPrivateAccess := false

	for _, block := range vpcConfigBlocks {
		if privateAccess, ok := block.GetBoolAttr("endpoint_private_access"); ok && privateAccess {
			hasPrivateAccess = true
			break
		}
	}

	if !hasPrivateAccess {
		findings = append(findings, model.Finding{
			RuleID:      "EKS-003",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "EKS cluster does not have private endpoint access enabled",
			Remediation: "Set endpoint_private_access to true in the vpc_config block to enable private communication between worker nodes and the API server",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
