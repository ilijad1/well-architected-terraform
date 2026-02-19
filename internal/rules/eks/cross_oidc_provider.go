package eks

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// CrossOIDCProviderRule checks that every EKS cluster has a corresponding
// aws_iam_openid_connect_provider for enabling IRSA (IAM Roles for Service Accounts).
type CrossOIDCProviderRule struct{}

func init() {
	engine.RegisterCross(&CrossOIDCProviderRule{})
}

func (r *CrossOIDCProviderRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EKS-008",
		Name:          "EKS Cluster Missing OIDC Provider",
		Description:   "EKS clusters should have an associated aws_iam_openid_connect_provider to enable IAM Roles for Service Accounts (IRSA), allowing fine-grained IAM permissions for Kubernetes workloads.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_eks_cluster", "aws_iam_openid_connect_provider"},
	}
}

func (r *CrossOIDCProviderRule) EvaluateAll(resources []model.TerraformResource) []model.Finding {
	// Collect OIDC provider URLs
	oidcURLs := make([]string, 0)
	for _, res := range resources {
		if res.Type == "aws_iam_openid_connect_provider" {
			url, ok := res.GetStringAttr("url")
			if ok && url != "" {
				oidcURLs = append(oidcURLs, url)
			}
		}
	}

	var findings []model.Finding
	for _, res := range resources {
		if res.Type != "aws_eks_cluster" {
			continue
		}

		if len(oidcURLs) == 0 {
			findings = append(findings, model.Finding{
				RuleID:      "EKS-008",
				RuleName:    "EKS Cluster Missing OIDC Provider",
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "No aws_iam_openid_connect_provider resource found in the plan. IRSA cannot be used without an OIDC provider.",
				Remediation: "Add an aws_iam_openid_connect_provider using the cluster's identity[0].oidc[0].issuer URL to enable IAM Roles for Service Accounts (IRSA).",
			})
			continue
		}

		clusterName, _ := res.GetStringAttr("name")

		// Check if any OIDC provider URL references this cluster or uses the EKS OIDC pattern
		found := false
		for _, url := range oidcURLs {
			if strings.Contains(url, "oidc.eks") ||
				(clusterName != "" && strings.Contains(url, clusterName)) {
				found = true
				break
			}
		}

		if !found {
			findings = append(findings, model.Finding{
				RuleID:      "EKS-008",
				RuleName:    "EKS Cluster Missing OIDC Provider",
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    res.Address(),
				File:        res.File,
				Line:        res.Line,
				Description: "No aws_iam_openid_connect_provider matching this EKS cluster was found in the plan.",
				Remediation: "Add an aws_iam_openid_connect_provider using the cluster's identity[0].oidc[0].issuer URL to enable IAM Roles for Service Accounts (IRSA).",
			})
		}
	}

	return findings
}
