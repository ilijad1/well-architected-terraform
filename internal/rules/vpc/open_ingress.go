package vpc

import (
	"fmt"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&OpenIngress{})
}

// OpenIngress checks that security groups don't allow unrestricted access on sensitive ports.
type OpenIngress struct{}

func (r *OpenIngress) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "VPC-001",
		Name:          "Security Group Open Ingress on Sensitive Ports",
		Description:   "Security groups should not allow unrestricted ingress (0.0.0.0/0) on sensitive ports like SSH, RDP, and database ports.",
		Severity:      model.SeverityCritical,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_security_group", "aws_security_group_rule"},
		DocURL:        "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
	}
}

// sensitivePorts maps port numbers to their service names.
var sensitivePorts = map[int]string{
	22:   "SSH",
	3389: "RDP",
	3306: "MySQL",
	5432: "PostgreSQL",
	1433: "MSSQL",
	6379: "Redis",
	27017: "MongoDB",
}

func (r *OpenIngress) Evaluate(resource model.TerraformResource) []model.Finding {
	if resource.Type == "aws_security_group" {
		return r.evaluateSecurityGroup(resource)
	}
	return r.evaluateSecurityGroupRule(resource)
}

func (r *OpenIngress) evaluateSecurityGroup(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	for _, ingress := range resource.GetBlocks("ingress") {
		if !hasOpenCIDR(ingress) {
			continue
		}

		fromPort := getPort(ingress.Attributes["from_port"])
		toPort := getPort(ingress.Attributes["to_port"])

		for port, service := range sensitivePorts {
			if portInRange(port, fromPort, toPort) {
				findings = append(findings, model.Finding{
					RuleID:      "VPC-001",
					RuleName:    r.Metadata().Name,
					Severity:    model.SeverityCritical,
					Pillar:      model.PillarSecurity,
					Resource:    resource.Address(),
					File:        resource.File,
					Line:        resource.Line,
					Description: fmt.Sprintf("Security group allows unrestricted ingress (0.0.0.0/0 or ::/0) on port %d (%s).", port, service),
					Remediation: fmt.Sprintf("Restrict ingress on port %d to specific CIDR blocks or security groups instead of 0.0.0.0/0.", port),
					DocURL:      r.Metadata().DocURL,
				})
			}
		}
	}

	return findings
}

func (r *OpenIngress) evaluateSecurityGroupRule(resource model.TerraformResource) []model.Finding {
	ruleType, _ := resource.GetStringAttr("type")
	if ruleType != "ingress" {
		return nil
	}

	if !hasOpenCIDRFromAttrs(resource.Attributes) {
		return nil
	}

	fromPort := getPort(resource.Attributes["from_port"])
	toPort := getPort(resource.Attributes["to_port"])

	var findings []model.Finding
	for port, service := range sensitivePorts {
		if portInRange(port, fromPort, toPort) {
			findings = append(findings, model.Finding{
				RuleID:      "VPC-001",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityCritical,
				Pillar:      model.PillarSecurity,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: fmt.Sprintf("Security group rule allows unrestricted ingress (0.0.0.0/0 or ::/0) on port %d (%s).", port, service),
				Remediation: fmt.Sprintf("Restrict ingress on port %d to specific CIDR blocks or security groups.", port),
				DocURL:      r.Metadata().DocURL,
			})
		}
	}

	return findings
}

func hasOpenCIDR(block model.Block) bool {
	return containsOpenCIDR(block.Attributes["cidr_blocks"]) ||
		containsOpenCIDR(block.Attributes["ipv6_cidr_blocks"])
}

func hasOpenCIDRFromAttrs(attrs map[string]interface{}) bool {
	return containsOpenCIDR(attrs["cidr_blocks"]) ||
		containsOpenCIDR(attrs["ipv6_cidr_blocks"])
}

func containsOpenCIDR(val interface{}) bool {
	cidrs, ok := val.([]interface{})
	if !ok {
		return false
	}
	for _, cidr := range cidrs {
		s, ok := cidr.(string)
		if ok && (s == "0.0.0.0/0" || s == "::/0") {
			return true
		}
	}
	return false
}

func getPort(val interface{}) int {
	switch v := val.(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		return -1
	}
}

func portInRange(port, from, to int) bool {
	if from < 0 || to < 0 {
		return false
	}
	return port >= from && port <= to
}
