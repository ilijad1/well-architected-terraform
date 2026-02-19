package eks

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&SecretsEncryption{})
}

type SecretsEncryption struct{}

func (r *SecretsEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EKS-001",
		Name:          "EKS Cluster Secrets Encryption",
		Description:   "Ensures EKS clusters have encryption enabled for secrets",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_eks_cluster"},
		DocURL:        "https://docs.aws.amazon.com/eks/latest/userguide/enable-kms.html",
	}
}

func (r *SecretsEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	if !resource.HasBlock("encryption_config") {
		findings = append(findings, model.Finding{
			RuleID:      "EKS-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "EKS cluster does not have encryption_config block configured",
			Remediation: "Add an encryption_config block with a KMS key and include 'secrets' in the resources list",
			DocURL:      r.Metadata().DocURL,
		})
		return findings
	}

	// Check if any encryption_config block has "secrets" in resources
	encryptionBlocks := resource.GetBlocks("encryption_config")
	hasSecretsEncryption := false

	for _, block := range encryptionBlocks {
		if resources, ok := block.Attributes["resources"].([]interface{}); ok {
			for _, res := range resources {
				if resStr, ok := res.(string); ok && resStr == "secrets" {
					hasSecretsEncryption = true
					break
				}
			}
		}
		if hasSecretsEncryption {
			break
		}
	}

	if !hasSecretsEncryption {
		findings = append(findings, model.Finding{
			RuleID:      "EKS-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "EKS cluster encryption_config does not include 'secrets' in resources",
			Remediation: "Update encryption_config to include 'secrets' in the resources list to encrypt Kubernetes secrets at rest",
			DocURL:      r.Metadata().DocURL,
		})
	}

	return findings
}
