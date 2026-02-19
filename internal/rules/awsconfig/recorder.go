// Package awsconfig contains Well-Architected rules for AWS AWSCONFIG resources.
package awsconfig

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&ConfigRecorder{})
	engine.Register(&ConfigRecorderStatus{})
	engine.Register(&ConfigDeliveryChannel{})
}

// ConfigRecorder checks that an AWS Config configuration recorder is defined.
type ConfigRecorder struct{}

func (r *ConfigRecorder) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CFG-001",
		Name:          "AWS Config Recorder Defined",
		Description:   "An AWS Config configuration recorder should be defined to record resource configuration changes.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_config_configuration_recorder"},
		DocURL:        "https://docs.aws.amazon.com/config/latest/developerguide/stop-start-recorder.html",
	}
}

func (r *ConfigRecorder) Evaluate(resource model.TerraformResource) []model.Finding {
	// Presence of the resource means a recorder is being configured.
	// Check that recording_group captures all resources.
	for _, rg := range resource.GetBlocks("recording_group") {
		if allSupported, ok := rg.GetBoolAttr("all_supported"); ok && !allSupported {
			return []model.Finding{{
				RuleID:      "CFG-001",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityHigh,
				Pillar:      model.PillarSecurity,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: "AWS Config recorder does not have all_supported = true in recording_group.",
				Remediation: "Set recording_group.all_supported = true to record all supported resource types.",
				DocURL:      r.Metadata().DocURL,
			}}
		}
	}
	return nil
}

// ConfigRecorderStatus checks that the AWS Config recorder is actively recording.
type ConfigRecorderStatus struct{}

func (r *ConfigRecorderStatus) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CFG-002",
		Name:          "AWS Config Recorder Enabled",
		Description:   "The AWS Config configuration recorder should be set to is_enabled = true.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_config_configuration_recorder_status"},
		DocURL:        "https://docs.aws.amazon.com/config/latest/developerguide/stop-start-recorder.html",
	}
}

func (r *ConfigRecorderStatus) Evaluate(resource model.TerraformResource) []model.Finding {
	if v, ok := resource.GetBoolAttr("is_enabled"); ok && !v {
		return []model.Finding{{
			RuleID:      "CFG-002",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityHigh,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "AWS Config recorder is not enabled (is_enabled = false).",
			Remediation: "Set is_enabled = true to start recording resource configuration changes.",
			DocURL:      r.Metadata().DocURL,
		}}
	}
	return nil
}

// ConfigDeliveryChannel checks that an AWS Config delivery channel is defined.
type ConfigDeliveryChannel struct{}

func (r *ConfigDeliveryChannel) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "CFG-003",
		Name:          "AWS Config Delivery Channel Defined",
		Description:   "An AWS Config delivery channel should be defined to store configuration snapshots in S3.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_config_delivery_channel"},
		DocURL:        "https://docs.aws.amazon.com/config/latest/developerguide/manage-delivery-channel.html",
	}
}

func (r *ConfigDeliveryChannel) Evaluate(resource model.TerraformResource) []model.Finding {
	s3Bucket, ok := resource.GetStringAttr("s3_bucket_name")
	if !ok || s3Bucket == "" {
		return []model.Finding{{
			RuleID:      "CFG-003",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "AWS Config delivery channel does not have an S3 bucket configured.",
			Remediation: "Set s3_bucket_name to an S3 bucket to store AWS Config snapshots and history.",
			DocURL:      r.Metadata().DocURL,
		}}
	}
	return nil
}
