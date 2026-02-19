package cognito

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&MFAConfiguration{})
	engine.Register(&AdvancedSecurity{})
	engine.Register(&DeletionProtection{})
	engine.Register(&PasswordPolicy{})
	engine.Register(&NoUnauthAccess{})
}

type MFAConfiguration struct{}

func (r *MFAConfiguration) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "COG-001", Name: "Cognito MFA Configuration", Description: "Cognito user pools should have MFA enabled.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_cognito_user_pool"}}
}

func (r *MFAConfiguration) Evaluate(resource model.TerraformResource) []model.Finding {
	mfa, ok := resource.GetStringAttr("mfa_configuration")
	if ok && mfa != "OFF" {
		return nil
	}
	return []model.Finding{{RuleID: "COG-001", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Cognito user pool does not have MFA enabled.", Remediation: "Set mfa_configuration to \"ON\" or \"OPTIONAL\"."}}
}

type AdvancedSecurity struct{}

func (r *AdvancedSecurity) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "COG-002", Name: "Cognito Advanced Security", Description: "Cognito user pools should have advanced security features enabled.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_cognito_user_pool"}}
}

func (r *AdvancedSecurity) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("user_pool_add_ons") {
		mode, ok := b.GetStringAttr("advanced_security_mode")
		if ok && (mode == "ENFORCED" || mode == "AUDIT") {
			return nil
		}
	}
	return []model.Finding{{RuleID: "COG-002", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Cognito user pool does not have advanced security enabled.", Remediation: "Add user_pool_add_ons block with advanced_security_mode = \"ENFORCED\" or \"AUDIT\"."}}
}

type DeletionProtection struct{}

func (r *DeletionProtection) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "COG-003", Name: "Cognito Deletion Protection", Description: "Cognito user pools should have deletion protection enabled.", Severity: model.SeverityMedium, Pillar: model.PillarReliability, ResourceTypes: []string{"aws_cognito_user_pool"}}
}

func (r *DeletionProtection) Evaluate(resource model.TerraformResource) []model.Finding {
	dp, ok := resource.GetStringAttr("deletion_protection")
	if ok && dp == "ACTIVE" {
		return nil
	}
	return []model.Finding{{RuleID: "COG-003", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarReliability, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Cognito user pool does not have deletion protection enabled.", Remediation: "Set deletion_protection = \"ACTIVE\"."}}
}

type PasswordPolicy struct{}

func (r *PasswordPolicy) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "COG-004", Name: "Cognito Password Policy", Description: "Cognito user pools should have strong password policy.", Severity: model.SeverityMedium, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_cognito_user_pool"}}
}

func (r *PasswordPolicy) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("password_policy") {
		minLen, ok := b.Attributes["minimum_length"]
		if !ok {
			continue
		}
		var length float64
		switch v := minLen.(type) {
		case float64:
			length = v
		case int:
			length = float64(v)
		}
		if length >= 12 {
			return nil
		}
	}
	return []model.Finding{{RuleID: "COG-004", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Cognito user pool password policy minimum length is less than 12.", Remediation: "Set minimum_length >= 12 in password_policy block."}}
}

type NoUnauthAccess struct{}

func (r *NoUnauthAccess) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "COG-005", Name: "Cognito No Unauthenticated Access", Description: "Cognito identity pools should not allow unauthenticated identities.", Severity: model.SeverityHigh, Pillar: model.PillarSecurity, ResourceTypes: []string{"aws_cognito_identity_pool"}}
}

func (r *NoUnauthAccess) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("allow_unauthenticated_identities"); ok && v {
		return []model.Finding{{RuleID: "COG-005", RuleName: r.Metadata().Name, Severity: model.SeverityHigh, Pillar: model.PillarSecurity, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Cognito identity pool allows unauthenticated identities.", Remediation: "Set allow_unauthenticated_identities = false."}}
	}
	return nil
}
