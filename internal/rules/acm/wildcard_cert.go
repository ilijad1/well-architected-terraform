package acm

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// WildcardCertRule checks for overly broad wildcard certificates.
type WildcardCertRule struct{}

func init() {
	engine.Register(&WildcardCertRule{})
}

func (r *WildcardCertRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ACM-002",
		Name:          "ACM Certificate Uses Wildcard Domain",
		Description:   "ACM certificates should avoid wildcard domains when the certificate is used for a single subdomain.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_acm_certificate"},
	}
}

func (r *WildcardCertRule) Evaluate(resource model.TerraformResource) []model.Finding {
	domain, ok := resource.GetStringAttr("domain_name")
	if !ok || domain == "" {
		return nil
	}

	if !strings.HasPrefix(domain, "*.") {
		return nil
	}

	// Check subject_alternative_names for non-wildcard entries that indicate
	// the cert is only used for specific subdomains (making the wildcard overly broad).
	// If there are no SANs, we can't determine scope — skip.
	sanAttr, hasSAN := resource.Attributes["subject_alternative_names"]
	if !hasSAN {
		return nil
	}

	sans, ok := sanAttr.([]interface{})
	if !ok || len(sans) == 0 {
		return nil
	}

	// If all SANs are also wildcards, the wildcard cert is intentional.
	hasSpecific := false
	for _, s := range sans {
		str, ok := s.(string)
		if !ok {
			continue
		}
		if str != domain && !strings.HasPrefix(str, "*.") {
			hasSpecific = true
			break
		}
	}

	if !hasSpecific {
		return nil
	}

	return []model.Finding{{
		RuleID:      "ACM-002",
		RuleName:    "ACM Certificate Uses Wildcard Domain",
		Severity:    model.SeverityLow,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This ACM certificate uses a wildcard domain (" + domain + ") but also has specific subdomain SANs, suggesting the wildcard is broader than necessary.",
		Remediation: "Issue certificates scoped to the specific subdomains needed rather than using a wildcard. This limits the blast radius if the certificate's private key is compromised.",
	}}
}
