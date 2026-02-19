package stepfunctions

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&Logging{})
	engine.Register(&Tracing{})
}

type Logging struct{}

func (r *Logging) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "SFN-001", Name: "Step Functions Logging", Description: "Step Functions state machines should have logging enabled.", Severity: model.SeverityMedium, Pillar: model.PillarOperationalExcellence, ResourceTypes: []string{"aws_sfn_state_machine"}}
}

func (r *Logging) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("logging_configuration") {
		if v, ok := b.GetStringAttr("level"); ok && v != "OFF" {
			return nil
		}
	}
	return []model.Finding{{RuleID: "SFN-001", RuleName: r.Metadata().Name, Severity: model.SeverityMedium, Pillar: model.PillarOperationalExcellence, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Step Functions state machine does not have logging enabled.", Remediation: "Add logging_configuration block with level set to ALL or ERROR."}}
}

type Tracing struct{}

func (r *Tracing) Metadata() model.RuleMetadata {
	return model.RuleMetadata{ID: "SFN-002", Name: "Step Functions Tracing", Description: "Step Functions state machines should have X-Ray tracing enabled.", Severity: model.SeverityLow, Pillar: model.PillarOperationalExcellence, ResourceTypes: []string{"aws_sfn_state_machine"}}
}

func (r *Tracing) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, b := range resource.GetBlocks("tracing_configuration") {
		if v, ok := b.GetBoolAttr("enabled"); ok && v {
			return nil
		}
	}
	return []model.Finding{{RuleID: "SFN-002", RuleName: r.Metadata().Name, Severity: model.SeverityLow, Pillar: model.PillarOperationalExcellence, Resource: resource.Address(), File: resource.File, Line: resource.Line, Description: "Step Functions state machine does not have X-Ray tracing enabled.", Remediation: "Add tracing_configuration block with enabled = true."}}
}
