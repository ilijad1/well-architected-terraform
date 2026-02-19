// Package transfer contains Well-Architected rules for AWS TRANSFER resources.
package transfer

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&NoFTP{})
	engine.Register(&LoggingRole{})
}

type NoFTP struct{}

func (r *NoFTP) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "TFR-001",
		Name:          "Transfer Server No FTP",
		Description:   "AWS Transfer servers should not use unencrypted FTP protocol.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_transfer_server"},
	}
}

func (r *NoFTP) Evaluate(resource model.TerraformResource) []model.Finding {
	if protos, ok := resource.Attributes["protocols"]; ok {
		if list, ok := protos.([]interface{}); ok {
			for _, p := range list {
				if s, ok := p.(string); ok && s == "FTP" {
					return []model.Finding{{
						RuleID:      "TFR-001",
						RuleName:    r.Metadata().Name,
						Severity:    model.SeverityHigh,
						Pillar:      model.PillarSecurity,
						Resource:    resource.Address(),
						File:        resource.File,
						Line:        resource.Line,
						Description: "Transfer server uses unencrypted FTP protocol.",
						Remediation: "Use SFTP or FTPS instead of FTP.",
					}}
				}
			}
		}
	}
	return nil
}

type LoggingRole struct{}

func (r *LoggingRole) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "TFR-002",
		Name:          "Transfer Server Logging Role",
		Description:   "AWS Transfer servers should have a logging role configured.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_transfer_server"},
	}
}

func (r *LoggingRole) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetStringAttr("logging_role"); ok && v != "" {
		return nil
	}
	return []model.Finding{{
		RuleID:      "TFR-002",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "Transfer server does not have a logging role configured.",
		Remediation: "Set logging_role to an IAM role ARN for CloudWatch logging.",
	}}
}
