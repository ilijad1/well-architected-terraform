package firehose

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&S3BackupEnabled{})
}

// S3BackupEnabled checks that Kinesis Firehose delivery streams with S3 extended configuration have backup enabled.
type S3BackupEnabled struct{}

func (r *S3BackupEnabled) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "KDF-002",
		Name:          "Kinesis Firehose S3 Backup Enabled",
		Description:   "Kinesis Firehose delivery streams should have S3 backup enabled to prevent data loss.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarReliability,
		ResourceTypes: []string{"aws_kinesis_firehose_delivery_stream"},
		DocURL:        "https://docs.aws.amazon.com/firehose/latest/dev/basic-deliver.html#s3-backup",
	}
}

func (r *S3BackupEnabled) Evaluate(resource model.TerraformResource) []model.Finding {
	// Check extended_s3_configuration for s3_backup_mode.
	// There is at most one such block; the rule only applies when it exists.
	blocks := resource.GetBlocks("extended_s3_configuration")
	if len(blocks) == 0 {
		return nil
	}
	if mode, ok := blocks[0].GetStringAttr("s3_backup_mode"); ok && mode == "Enabled" {
		return nil
	}
	return []model.Finding{{
		RuleID:      "KDF-002",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarReliability,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "Kinesis Firehose delivery stream extended S3 configuration does not have S3 backup enabled.",
		Remediation: "Set s3_backup_mode = \"Enabled\" in the extended_s3_configuration block to retain a copy of all source records.",
		DocURL:      r.Metadata().DocURL,
	}}
}
