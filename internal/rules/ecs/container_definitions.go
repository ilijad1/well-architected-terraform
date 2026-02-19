package ecs

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

type containerDefinition struct {
	Name             string            `json:"name"`
	Privileged       bool              `json:"privileged"`
	ReadonlyRootFS   bool              `json:"readonlyRootFilesystem"`
	Environment      []envVar          `json:"environment"`
	LogConfiguration *logConfiguration `json:"logConfiguration"`
}

type envVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type logConfiguration struct {
	LogDriver string `json:"logDriver"`
}

func parseContainerDefinitions(resource model.TerraformResource) []containerDefinition {
	raw, ok := resource.GetStringAttr("container_definitions")
	if !ok {
		return nil
	}

	var defs []containerDefinition
	if err := json.Unmarshal([]byte(raw), &defs); err != nil {
		return nil
	}
	return defs
}

func init() {
	engine.Register(&NoPrivileged{})
	engine.Register(&ReadonlyRoot{})
	engine.Register(&NoSecretsInEnv{})
	engine.Register(&LogConfig{})
}

// NoPrivileged checks that ECS task definitions do not run privileged containers (ECS-002).
type NoPrivileged struct{}

func (r *NoPrivileged) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ECS-002",
		Name:          "ECS No Privileged Containers",
		Description:   "ECS task definitions should not run privileged containers.",
		Severity:      model.SeverityCritical,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_ecs_task_definition"},
	}
}

func (r *NoPrivileged) Evaluate(resource model.TerraformResource) []model.Finding {
	defs := parseContainerDefinitions(resource)
	for _, def := range defs {
		if def.Privileged {
			return []model.Finding{{
				RuleID:      "ECS-002",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityCritical,
				Pillar:      model.PillarSecurity,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: fmt.Sprintf("ECS container '%s' is running in privileged mode.", def.Name),
				Remediation: "Set privileged = false in container definitions.",
			}}
		}
	}
	return nil
}

// ReadonlyRoot checks that ECS containers use a readonly root filesystem (ECS-003).
type ReadonlyRoot struct{}

func (r *ReadonlyRoot) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ECS-003",
		Name:          "ECS Readonly Root Filesystem",
		Description:   "ECS containers should use readonly root filesystem.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_ecs_task_definition"},
	}
}

func (r *ReadonlyRoot) Evaluate(resource model.TerraformResource) []model.Finding {
	defs := parseContainerDefinitions(resource)
	var findings []model.Finding
	for _, def := range defs {
		if !def.ReadonlyRootFS {
			findings = append(findings, model.Finding{
				RuleID:      "ECS-003",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: fmt.Sprintf("ECS container '%s' does not have readonly root filesystem.", def.Name),
				Remediation: "Set readonlyRootFilesystem = true in container definitions.",
			})
		}
	}
	return findings
}

// NoSecretsInEnv checks that ECS containers do not expose secrets via environment variables (ECS-004).
type NoSecretsInEnv struct{}

var sensitiveEnvPatterns = []string{"SECRET", "PASSWORD", "TOKEN", "API_KEY", "PRIVATE_KEY"}

func (r *NoSecretsInEnv) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ECS-004",
		Name:          "ECS No Secrets in Environment Variables",
		Description:   "ECS containers should not have secrets in environment variable names.",
		Severity:      model.SeverityCritical,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_ecs_task_definition"},
	}
}

func (r *NoSecretsInEnv) Evaluate(resource model.TerraformResource) []model.Finding {
	defs := parseContainerDefinitions(resource)
	var findings []model.Finding
	for _, def := range defs {
		for _, env := range def.Environment {
			upper := strings.ToUpper(env.Name)
			for _, pattern := range sensitiveEnvPatterns {
				if strings.Contains(upper, pattern) {
					findings = append(findings, model.Finding{
						RuleID:      "ECS-004",
						RuleName:    r.Metadata().Name,
						Severity:    model.SeverityCritical,
						Pillar:      model.PillarSecurity,
						Resource:    resource.Address(),
						File:        resource.File,
						Line:        resource.Line,
						Description: fmt.Sprintf("ECS container '%s' has potentially sensitive environment variable '%s'.", def.Name, env.Name),
						Remediation: "Use AWS Secrets Manager or SSM Parameter Store instead of environment variables for secrets.",
					})
					break
				}
			}
		}
	}
	return findings
}

// LogConfig checks that ECS containers have log configuration for observability (ECS-005).
type LogConfig struct{}

func (r *LogConfig) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "ECS-005",
		Name:          "ECS Container Log Configuration",
		Description:   "ECS containers should have log configuration for observability.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarOperationalExcellence,
		ResourceTypes: []string{"aws_ecs_task_definition"},
	}
}

func (r *LogConfig) Evaluate(resource model.TerraformResource) []model.Finding {
	defs := parseContainerDefinitions(resource)
	var findings []model.Finding
	for _, def := range defs {
		if def.LogConfiguration == nil {
			findings = append(findings, model.Finding{
				RuleID:      "ECS-005",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityMedium,
				Pillar:      model.PillarOperationalExcellence,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: fmt.Sprintf("ECS container '%s' does not have log configuration.", def.Name),
				Remediation: "Add logConfiguration to container definitions for centralized logging.",
			})
		}
	}
	return findings
}
