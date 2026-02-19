package cloudtrail

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&S3DataEvents{})
}

// S3DataEvents checks that CloudTrail is configured to log S3 data events.
type S3DataEvents struct{}

func (r *S3DataEvents) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CT-006",
		Name:          "CloudTrail S3 Data Events Enabled",
		Description:   "CloudTrail should log S3 data events (object-level API operations) for security and compliance.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_cloudtrail"},
		DocURL:        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html",
	}
}

func (r *S3DataEvents) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, eventSelector := range resource.GetBlocks("event_selector") {
		for _, dataResource := range eventSelector.Blocks["data_resource"] {
			if t, ok := dataResource.GetStringAttr("type"); ok && t == "AWS::S3::Object" {
				return nil
			}
		}
	}
	return []model.Finding{{
		RuleID:      "CT-006",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "CloudTrail does not have S3 data events logging configured.",
		Remediation: "Add an event_selector block with a data_resource of type AWS::S3::Object to capture S3 object-level API calls.",
		DocURL:      r.Metadata().DocURL,
	}}
}
