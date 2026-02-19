package ec2

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&EBSOptimized{})
}

// EBSOptimized checks that EC2 instances are EBS-optimized.
type EBSOptimized struct{}

func (r *EBSOptimized) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC2-010",
		Name:          "EC2 Instance EBS Optimized",
		Description:   "EC2 instances should be EBS-optimized to provide dedicated throughput between EC2 and EBS.",
		Severity:      model.SeverityLow,
		Pillar:        model.PillarPerformanceEfficiency,
		ResourceTypes: []string{"aws_instance"},
		DocURL:        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-optimized.html",
	}
}

func (r *EBSOptimized) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("ebs_optimized"); ok && v {
		return nil
	}
	return []model.Finding{{
		RuleID:      "EC2-010",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityLow,
		Pillar:      model.PillarPerformanceEfficiency,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "EC2 instance is not EBS-optimized, which may result in shared network bandwidth between EBS and other traffic.",
		Remediation: "Set ebs_optimized = true to provide dedicated throughput between EC2 and EBS storage.",
		DocURL:      r.Metadata().DocURL,
	}}
}
