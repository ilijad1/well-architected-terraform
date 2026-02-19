package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func TestParsePlanFile_SamplePlan(t *testing.T) {
	resources, err := ParsePlanFile("../../testdata/plan/sample.json")
	require.NoError(t, err)

	// Root: 3 resources (s3_bucket, instance, data source)
	// module.vpc: 2 resources (vpc, subnet)
	// module.vpc.module.security: 1 resource (security_group)
	// module.eks: 1 resource (eks_cluster)
	assert.Len(t, resources, 7)

	// Check root-level resource
	bucket := findPlanResource(resources, "aws_s3_bucket", "root_bucket")
	require.NotNil(t, bucket)
	assert.Equal(t, "aws_s3_bucket.root_bucket", bucket.FullAddress)
	assert.Equal(t, "aws_s3_bucket.root_bucket", bucket.Address())
	assert.Equal(t, "tfplan", bucket.File)
	assert.Equal(t, 0, bucket.Line)
	assert.Equal(t, "my-root-bucket", bucket.Attributes["bucket"])

	// Check tags are parsed as attributes (map)
	tags, ok := bucket.Attributes["tags"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "production", tags["Environment"])

	// Check blocks are detected (server_side_encryption_configuration is []map)
	assert.True(t, bucket.HasBlock("server_side_encryption_configuration"))

	// Check data source has data. prefix
	dataSource := findPlanResource(resources, "data.aws_iam_policy_document", "example")
	require.NotNil(t, dataSource)
	assert.Equal(t, "data.aws_iam_policy_document", dataSource.Type)

	// Check module resources have full addresses
	vpc := findPlanResource(resources, "aws_vpc", "this")
	require.NotNil(t, vpc)
	assert.Equal(t, "module.vpc.aws_vpc.this", vpc.FullAddress)
	assert.Equal(t, "module.vpc.aws_vpc.this", vpc.Address())

	// Check nested module resources
	sg := findPlanResource(resources, "aws_security_group", "default")
	require.NotNil(t, sg)
	assert.Equal(t, "module.vpc.module.security.aws_security_group.default", sg.FullAddress)

	// Check ingress block detected on security group
	assert.True(t, sg.HasBlock("ingress"))
	ingressBlocks := sg.GetBlocks("ingress")
	require.Len(t, ingressBlocks, 1)

	// Check EKS cluster from module
	eks := findPlanResource(resources, "aws_eks_cluster", "this")
	require.NotNil(t, eks)
	assert.Equal(t, "module.eks.aws_eks_cluster.this", eks.FullAddress)

	// Check EKS has encryption_config and vpc_config blocks
	assert.True(t, eks.HasBlock("encryption_config"))
	assert.True(t, eks.HasBlock("vpc_config"))

	// Verify vpc_config block attributes
	vpcConfigs := eks.GetBlocks("vpc_config")
	require.Len(t, vpcConfigs, 1)
	epPriv, ok := vpcConfigs[0].GetBoolAttr("endpoint_private_access")
	assert.True(t, ok)
	assert.True(t, epPriv)
}

func TestParsePlanFile_NotFound(t *testing.T) {
	_, err := ParsePlanFile("nonexistent.json")
	assert.Error(t, err)
}

func TestParsePlanFile_InvalidJSON(t *testing.T) {
	_, err := ParsePlanFile("../../go.mod")
	assert.Error(t, err)
}

func TestParsePlanFile_EmptyPlan(t *testing.T) {
	resources, err := ParsePlanFile("../../testdata/plan/empty.json")
	require.NoError(t, err)
	assert.Len(t, resources, 0)
}

func findPlanResource(resources []model.TerraformResource, resType, name string) *model.TerraformResource {
	for i, r := range resources {
		if r.Type == resType && r.Name == name {
			return &resources[i]
		}
	}
	return nil
}
