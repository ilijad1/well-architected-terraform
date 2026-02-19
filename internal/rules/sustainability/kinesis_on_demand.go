package sustainability

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// KinesisOnDemandRule checks if Kinesis streams use on-demand mode for efficient scaling.
type KinesisOnDemandRule struct{}

func init() {
	engine.Register(&KinesisOnDemandRule{})
}

func (r *KinesisOnDemandRule) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SUS-013",
		Name:          "Kinesis Stream Not On-Demand",
		Description:   "Kinesis streams should use ON_DEMAND mode to automatically scale capacity and avoid over-provisioning shards, reducing cost and resource waste.",
		Severity:      model.SeverityInfo,
		Pillar:        model.PillarSustainability,
		ResourceTypes: []string{"aws_kinesis_stream"},
	}
}

func (r *KinesisOnDemandRule) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, block := range resource.GetBlocks("stream_mode_details") {
		mode, ok := block.GetStringAttr("stream_mode")
		if ok && mode == "ON_DEMAND" {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "SUS-013",
		RuleName:    "Kinesis Stream Not On-Demand",
		Severity:    model.SeverityInfo,
		Pillar:      model.PillarSustainability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "This Kinesis stream is not using ON_DEMAND mode. Provisioned mode with fixed shards can lead to over-provisioning and wasted capacity.",
		Remediation: "Add a stream_mode_details block with stream_mode = \"ON_DEMAND\" to automatically scale stream capacity based on throughput.",
	}}
}
