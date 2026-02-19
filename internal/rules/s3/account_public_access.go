// Package s3 contains Well-Architected rules for AWS S3 resources.
package s3

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&AccountPublicAccessBlock{})
}

// AccountPublicAccessBlock checks that the S3 account-level public access block is configured.
type AccountPublicAccessBlock struct{}

func (r *AccountPublicAccessBlock) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "S3-007",
		Name:          "S3 Account Public Access Block",
		Description:   "The S3 account-level public access block should have all four block settings enabled.",
		Severity:      model.SeverityCritical,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_s3_account_public_access_block"},
		DocURL:        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
	}
}

func (r *AccountPublicAccessBlock) Evaluate(resource model.TerraformResource) []model.Finding {
	flags := []string{
		"block_public_acls",
		"block_public_policy",
		"ignore_public_acls",
		"restrict_public_buckets",
	}

	for _, flag := range flags {
		v, ok := resource.GetBoolAttr(flag)
		if !ok || !v {
			return []model.Finding{{
				RuleID:      "S3-007",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityCritical,
				Pillar:      model.PillarSecurity,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: "S3 account-level public access block does not have all four block settings enabled (block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets).",
				Remediation: "Set all four flags to true in aws_s3_account_public_access_block.",
				DocURL:      r.Metadata().DocURL,
			}}
		}
	}
	return nil
}
