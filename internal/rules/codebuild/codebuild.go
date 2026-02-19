// Package codebuild contains Well-Architected rules for AWS CODEBUILD resources.
package codebuild

import (
	"fmt"
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ArtifactEncryption{})
	engine.Register(&NoSecretsInEnv{})
	engine.Register(&LogsConfig{})
	engine.Register(&NoPrivilegedMode{})
}

type ArtifactEncryption struct{}

func (r *ArtifactEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "CB-001", Name: "CodeBuild Artifact Encryption", Description: "CodeBuild projects should not disable artifact encryption.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_codebuild_project"}}
}

func (r *ArtifactEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("artifacts") {
		if v, ok := b.GetBoolAttr("encryption_disabled"); ok && v {
			return []model.Finding{{RuleID: "CB-001", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "CodeBuild project has artifact encryption disabled.", Remediation: "Remove encryption_disabled or set it to false."}}
		}
	}
	return nil
}

var sensitiveEnvPatterns = []string{"SECRET", "PASSWORD", "KEY", "TOKEN"}

type NoSecretsInEnv struct{}

func (r *NoSecretsInEnv) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "CB-002", Name: "CodeBuild No Secrets in Environment", Description: "CodeBuild environment variables should not contain secrets.", Severity: model.SeverityCritical, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_codebuild_project"}}
}

func (r *NoSecretsInEnv) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding
	for _, env := range resource.GetBlocks("environment") {
		for _, ev := range env.Blocks["environment_variable"] {
			name, _ := ev.GetStringAttr("name")
			evType, _ := ev.GetStringAttr("type")
			if evType == "PARAMETER_STORE" || evType == "SECRETS_MANAGER" {
				continue
			}
			upper := strings.ToUpper(name)
			for _, pattern := range sensitiveEnvPatterns {
				if strings.Contains(upper, pattern) {
					findings = append(findings, model.Finding{RuleID: "CB-002", RuleName: r.Metadata().Name, Severity: model.SeverityCritical, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: fmt.Sprintf("CodeBuild environment variable '%s' may contain a secret as plaintext.", name), Remediation: "Use PARAMETER_STORE or SECRETS_MANAGER type for sensitive environment variables."})
					break
				}
			}
		}
	}
	return findings
}

type LogsConfig struct{}

func (r *LogsConfig) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "CB-003", Name: "CodeBuild Logs Configuration", Description: "CodeBuild projects should have logs configuration.", Severity: model.SeverityMedium, Pillar: model.PillarOperationalExcellence, ResourceTypes: []string{"aws_codebuild_project"}}
}

func (r *LogsConfig) Evaluate(resource model.TerraformResource) []model.Finding {
	if resource.HasBlock("logs_config") {
		return nil
	}
	return []model.Finding{{RuleID: "CB-003", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarOperationalExcellence, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "CodeBuild project does not have logs configuration.", Remediation: "Add logs_config block with cloudwatch_logs or s3_logs."}}
}

type NoPrivilegedMode struct{}

func (r *NoPrivilegedMode) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "CB-004", Name: "CodeBuild No Privileged Mode", Description: "CodeBuild projects should not run in privileged mode unless building Docker images.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_codebuild_project"}}
}

func (r *NoPrivilegedMode) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, env := range resource.GetBlocks("environment") {
		if v, ok := env.GetBoolAttr("privileged_mode"); ok && v {
			return []model.Finding{{RuleID: "CB-004", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "CodeBuild project has privileged mode enabled.", Remediation: "Set privileged_mode = false unless building Docker images."}}
		}
	}
	return nil
}
