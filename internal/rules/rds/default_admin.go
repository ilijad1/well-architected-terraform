package rds

import (
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&DefaultAdmin{})
}

var defaultAdminUsernames = map[string]bool{
	"admin":    true,
	"postgres": true,
	"root":     true,
	"master":   true,
}

// DefaultAdmin checks that RDS instances do not use a default/well-known admin username.
type DefaultAdmin struct{}

func (r *DefaultAdmin) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "RDS-015",
		Name:          "RDS Default Admin Username",
		Description:   "RDS instances should not use default admin usernames (admin, postgres, root, master) to reduce attack surface.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_db_instance"},
		DocURL:        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.Security.html",
	}
}

func (r *DefaultAdmin) Evaluate(resource model.TerraformResource) []model.Finding {
	username, ok := resource.GetStringAttr("username")
	if !ok || username == "" {
		return nil
	}
	if defaultAdminUsernames[strings.ToLower(username)] {
		return []model.Finding{{
			RuleID:      "RDS-015",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "RDS instance uses a default admin username '" + username + "'. Default usernames are well-known and increase brute-force risk.",
			Remediation: "Use a non-default username for the master database user (not admin, postgres, root, or master).",
			DocURL:      r.Metadata().DocURL,
		}}
	}
	return nil
}
