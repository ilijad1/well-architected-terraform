package emr

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&KerberosAuth{})
	engine.Register(&SubnetPlacement{})
	engine.Register(&LogURI{})
	engine.Register(&SecurityConfig{})
}

type KerberosAuth struct{}

func (r *KerberosAuth) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "EMR-001", Name: "EMR Kerberos Authentication", Description: "EMR clusters should use Kerberos authentication.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_emr_cluster"}}
}

func (r *KerberosAuth) Evaluate(resource model.TerraformResource) []model.Finding {
	if len(resource.GetBlocks("kerberos_attributes")) > 0 {
		return nil
	}
	return []model.Finding{{RuleID: "EMR-001", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "EMR cluster does not have Kerberos authentication configured.", Remediation: "Add kerberos_attributes block."}}
}

type SubnetPlacement struct{}

func (r *SubnetPlacement) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "EMR-002", Name: "EMR Cluster Subnet Placement", Description: "EMR clusters should be deployed in a VPC subnet.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_emr_cluster"}}
}

func (r *SubnetPlacement) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("ec2_attributes") {
		if v, ok := b.GetStringAttr("subnet_id"); ok && v != "" {
			return nil
		}
	}
	return []model.Finding{{RuleID: "EMR-002", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "EMR cluster is not deployed in a VPC subnet.", Remediation: "Set ec2_attributes.subnet_id to place the cluster in a VPC."}}
}

type LogURI struct{}

func (r *LogURI) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "EMR-003", Name: "EMR Cluster Logging", Description: "EMR clusters should have logging configured.", Severity: model.SeverityMedium, Pillar: model.PillarOperationalExcellence, ResourceTypes: []string{"aws_emr_cluster"}}
}

func (r *LogURI) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetStringAttr("log_uri"); ok && v != "" {
		return nil
	}
	return []model.Finding{{RuleID: "EMR-003", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarOperationalExcellence, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "EMR cluster does not have logging configured.", Remediation: "Set log_uri to an S3 path for cluster logs."}}
}

type SecurityConfig struct{}

func (r *SecurityConfig) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "EMR-004", Name: "EMR Security Configuration", Description: "EMR clusters should have a security configuration attached.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_emr_cluster"}}
}

func (r *SecurityConfig) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetStringAttr("security_configuration"); ok && v != "" {
		return nil
	}
	return []model.Finding{{RuleID: "EMR-004", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "EMR cluster does not have a security configuration attached.", Remediation: "Set security_configuration to reference an aws_emr_security_configuration."}}
}
