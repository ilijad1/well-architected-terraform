package s3

import (
	"fmt"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&PublicAccessBlock{})
}

// PublicAccessBlock checks that S3 bucket public access blocks are fully enabled.
type PublicAccessBlock struct{}

func (r *PublicAccessBlock) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "S3-002",
		Name:          "S3 Public Access Block",
		Description:   "S3 bucket public access block should have all four settings enabled to prevent public access.",
		Severity:      model.SeverityCritical,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_s3_bucket_public_access_block"},
		DocURL:        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
	}
}

var publicAccessAttrs = []string{
	"block_public_acls",
	"block_public_policy",
	"ignore_public_acls",
	"restrict_public_buckets",
}

func (r *PublicAccessBlock) Evaluate(resource model.TerraformResource) []model.Finding {
	var findings []model.Finding

	for _, attr := range publicAccessAttrs {
		val, ok := resource.GetBoolAttr(attr)
		if !ok || !val {
			findings = append(findings, model.Finding{
				RuleID:      "S3-002",
				RuleName:    r.Metadata().Name,
				Severity:    model.SeverityCritical,
				Pillar:      model.PillarSecurity,
				Resource:    resource.Address(),
				File:        resource.File,
				Line:        resource.Line,
				Description: fmt.Sprintf("Public access block setting '%s' is not set to true.", attr),
				Remediation: fmt.Sprintf("Set '%s = true' in the aws_s3_bucket_public_access_block resource.", attr),
				DocURL:      r.Metadata().DocURL,
			})
		}
	}

	return findings
}
