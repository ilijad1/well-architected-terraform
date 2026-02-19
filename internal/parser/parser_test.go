package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFile_S3Good(t *testing.T) {
	p := New()
	resources, err := p.ParseFile("../../testdata/s3/good.tf")
	require.NoError(t, err)
	assert.Len(t, resources, 7)

	// Check the S3 bucket
	bucket := resources[0]
	assert.Equal(t, "aws_s3_bucket", bucket.Type)
	assert.Equal(t, "encrypted_bucket", bucket.Name)
	assert.Equal(t, "my-encrypted-bucket", bucket.Attributes["bucket"])

	// Check tags are parsed
	tags, ok := bucket.Attributes["tags"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "production", tags["Environment"])

	// Check encryption configuration resource
	enc := resources[1]
	assert.Equal(t, "aws_s3_bucket_server_side_encryption_configuration", enc.Type)
	assert.True(t, enc.HasBlock("rule"))

	// Check public access block
	pab := resources[2]
	assert.Equal(t, "aws_s3_bucket_public_access_block", pab.Type)
	blockPublicAcls, ok := pab.GetBoolAttr("block_public_acls")
	assert.True(t, ok)
	assert.True(t, blockPublicAcls)
}

func TestParseFile_S3Bad(t *testing.T) {
	p := New()
	resources, err := p.ParseFile("../../testdata/s3/bad.tf")
	require.NoError(t, err)
	assert.Len(t, resources, 4)

	bucket := resources[0]
	assert.Equal(t, "aws_s3_bucket", bucket.Type)
	assert.Equal(t, "unencrypted_bucket", bucket.Name)

	// Partial public access block
	pab := resources[1]
	blockPolicy, ok := pab.GetBoolAttr("block_public_policy")
	assert.True(t, ok)
	assert.False(t, blockPolicy)
}

func TestParseFile_VPC(t *testing.T) {
	p := New()
	resources, err := p.ParseFile("../../testdata/vpc/bad.tf")
	require.NoError(t, err)
	assert.Len(t, resources, 6)

	sg := resources[0]
	assert.Equal(t, "aws_security_group", sg.Type)
	assert.Equal(t, "open_ssh", sg.Name)

	// Check ingress blocks
	ingress := sg.GetBlocks("ingress")
	assert.Len(t, ingress, 2)

	// First ingress: SSH from 0.0.0.0/0
	fromPort, ok := ingress[0].Attributes["from_port"].(float64)
	assert.True(t, ok)
	assert.Equal(t, float64(22), fromPort)

	cidrBlocks, ok := ingress[0].Attributes["cidr_blocks"].([]interface{})
	assert.True(t, ok)
	assert.Contains(t, cidrBlocks, "0.0.0.0/0")
}

func TestParseDirectory(t *testing.T) {
	p := New()
	resources, err := p.ParseDirectory("../../testdata/s3")
	require.NoError(t, err)
	assert.True(t, len(resources) > 0, "should find resources in testdata/s3")
}

func TestParseFile_NonExistent(t *testing.T) {
	p := New()
	_, err := p.ParseFile("nonexistent.tf")
	assert.Error(t, err)
}
