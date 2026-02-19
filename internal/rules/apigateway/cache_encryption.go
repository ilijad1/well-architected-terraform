package apigateway

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&CacheEncryption{})
}

type CacheEncryption struct{}

func (r *CacheEncryption) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "APIGW-004",
		Name:          "API Gateway Cache Data Encrypted",
		Description:   "API Gateway method settings should have cache data encryption enabled.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_api_gateway_method_settings"},
	}
}

func (r *CacheEncryption) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, settings := range resource.GetBlocks("settings") {
		encrypted, ok := settings.GetBoolAttr("cache_data_encrypted")
		if ok && encrypted {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "APIGW-004",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "API Gateway method settings do not have cache data encryption enabled.",
		Remediation: "Set cache_data_encrypted = true in the settings block.",
	}}
}
