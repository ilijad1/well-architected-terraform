package ec2

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&IMDSv2{})
}

// IMDSv2 checks that EC2 instances require IMDSv2.
type IMDSv2 struct{}

func (r *IMDSv2) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "EC2-001",
		Name:          "EC2 IMDSv2 Required",
		Description:   "EC2 instances should require IMDSv2 to prevent SSRF-based credential theft.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_instance", "aws_launch_template"},
		DocURL:        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
	}
}

func (r *IMDSv2) Evaluate(resource model.TerraformResource) []model.Finding {
	blocks := resource.GetBlocks("metadata_options")
	if len(blocks) > 0 {
		tokens, ok := blocks[0].GetStringAttr("http_tokens")
		if ok && tokens == "required" {
			return nil
		}
	}

	return []model.Finding{{
		RuleID:      "EC2-001",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityHigh,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "EC2 instance does not require IMDSv2. The instance metadata service v1 is vulnerable to SSRF attacks.",
		Remediation: "Add metadata_options block with http_tokens = \"required\" to enforce IMDSv2.",
		DocURL:      r.Metadata().DocURL,
	}}
}
