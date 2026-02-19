package s3

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&OwnershipControls{})
}

// OwnershipControls checks that S3 bucket ownership controls enforce bucket owner ownership.
type OwnershipControls struct{}

func (r *OwnershipControls) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "S3-008",
		Name:          "S3 Bucket Ownership Controls",
		Description:   "S3 bucket ownership controls should be set to BucketOwnerEnforced to disable ACLs.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_s3_bucket_ownership_controls"},
		DocURL:        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html",
	}
}

func (r *OwnershipControls) Evaluate(resource model.TerraformResource) []model.Finding {
	for _, ruleBlock := range resource.GetBlocks("rule") {
		ownership, ok := ruleBlock.GetStringAttr("object_ownership")
		if ok && ownership == "BucketOwnerEnforced" {
			return nil
		}
	}
	return []model.Finding{{
		RuleID:      "S3-008",
		RuleName:    r.Metadata().Name,
		Severity:    model.SeverityMedium,
		Pillar:      model.PillarSecurity,
		Resource:    resource.Address(),
		File:        resource.File,
		Line:        resource.Line,
		Description: "S3 bucket ownership controls do not enforce BucketOwnerEnforced, which allows ACL-based access.",
		Remediation: "Set rule.object_ownership = \"BucketOwnerEnforced\" to disable ACLs and enforce bucket owner ownership.",
		DocURL:      r.Metadata().DocURL,
	}}
}
