package eks

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/stretchr/testify/assert"
)

// SecretsEncryption Tests
func TestSecretsEncryption_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_cluster",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"encryption_config": {{
				Type: "encryption_config",
				Attributes: map[string]interface{}{
					"resources": []interface{}{"secrets"},
				},
			}},
		},
	}
	rule := &SecretsEncryption{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestSecretsEncryption_Fail_NoBlock(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_eks_cluster",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &SecretsEncryption{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EKS-001", findings[0].RuleID)
}

func TestSecretsEncryption_Fail_NoSecretsInResources(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_cluster",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"encryption_config": {{
				Type: "encryption_config",
				Attributes: map[string]interface{}{
					"resources": []interface{}{"other"},
				},
			}},
		},
	}
	rule := &SecretsEncryption{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EKS-001", findings[0].RuleID)
}

// ClusterLogging Tests
func TestClusterLogging_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_cluster",
		Name: "test",
		Attributes: map[string]interface{}{
			"enabled_cluster_log_types": []interface{}{"api", "audit"},
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &ClusterLogging{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestClusterLogging_Fail_NoAudit(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_cluster",
		Name: "test",
		Attributes: map[string]interface{}{
			"enabled_cluster_log_types": []interface{}{"api"},
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &ClusterLogging{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EKS-002", findings[0].RuleID)
}

func TestClusterLogging_Fail_Empty(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_eks_cluster",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &ClusterLogging{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EKS-002", findings[0].RuleID)
}

// PrivateEndpoint Tests
func TestPrivateEndpoint_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_cluster",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"vpc_config": {{
				Type: "vpc_config",
				Attributes: map[string]interface{}{
					"endpoint_private_access": true,
				},
			}},
		},
	}
	rule := &PrivateEndpoint{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestPrivateEndpoint_Fail_NoBlock(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_eks_cluster",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &PrivateEndpoint{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EKS-003", findings[0].RuleID)
}

func TestPrivateEndpoint_Fail_NotEnabled(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_cluster",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"vpc_config": {{
				Type: "vpc_config",
				Attributes: map[string]interface{}{
					"endpoint_private_access": false,
				},
			}},
		},
	}
	rule := &PrivateEndpoint{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EKS-003", findings[0].RuleID)
}

// PublicEndpoint Tests
func TestPublicEndpoint_Pass_Disabled(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_cluster",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"vpc_config": {{
				Type: "vpc_config",
				Attributes: map[string]interface{}{
					"endpoint_public_access": false,
				},
			}},
		},
	}
	rule := &PublicEndpoint{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestPublicEndpoint_Pass_RestrictedCIDR(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_cluster",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"vpc_config": {{
				Type: "vpc_config",
				Attributes: map[string]interface{}{
					"endpoint_public_access": true,
					"public_access_cidrs":    []interface{}{"10.0.0.0/8"},
				},
			}},
		},
	}
	rule := &PublicEndpoint{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestPublicEndpoint_Fail_NoBlock(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_eks_cluster",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &PublicEndpoint{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EKS-004", findings[0].RuleID)
}

func TestPublicEndpoint_Fail_UnrestrictedCIDR(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_cluster",
		Name: "test",
		Attributes: map[string]interface{}{},
		Blocks: map[string][]model.Block{
			"vpc_config": {{
				Type: "vpc_config",
				Attributes: map[string]interface{}{
					"endpoint_public_access": true,
					"public_access_cidrs":    []interface{}{"0.0.0.0/0"},
				},
			}},
		},
	}
	rule := &PublicEndpoint{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EKS-004", findings[0].RuleID)
}

// NodeGroupTags Tests
func TestNodeGroupTags_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_node_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"tags": map[string]interface{}{
				"Environment": "production",
			},
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &NodeGroupTags{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestNodeGroupTags_Fail_NoTags(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_eks_node_group",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &NodeGroupTags{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EKS-005", findings[0].RuleID)
}

func TestNodeGroupTags_Fail_EmptyTags(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_node_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"tags": map[string]interface{}{},
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &NodeGroupTags{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EKS-005", findings[0].RuleID)
}

// NodeGroupInstanceTypes Tests
func TestNodeGroupInstanceTypes_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_node_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"instance_types": []interface{}{"t3.medium"},
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &NodeGroupInstanceTypes{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestNodeGroupInstanceTypes_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_eks_node_group",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &NodeGroupInstanceTypes{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EKS-006", findings[0].RuleID)
}

func TestNodeGroupInstanceTypes_Fail_Empty(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_node_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"instance_types": []interface{}{},
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &NodeGroupInstanceTypes{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EKS-006", findings[0].RuleID)
}

// ClusterVersion Tests
func TestClusterVersion_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_cluster",
		Name: "test",
		Attributes: map[string]interface{}{
			"version": "1.28",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &ClusterVersion{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestClusterVersion_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_eks_cluster",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &ClusterVersion{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EKS-007", findings[0].RuleID)
}

func TestClusterVersion_Fail_Empty(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_eks_cluster",
		Name: "test",
		Attributes: map[string]interface{}{
			"version": "",
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &ClusterVersion{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EKS-007", findings[0].RuleID)
}

// --- EKS-008: Cross OIDC Provider ---

func makeEKSRes(resType, name string, attrs map[string]interface{}) model.TerraformResource {
	return model.TerraformResource{
		Type:       resType,
		Name:       name,
		Attributes: attrs,
		Blocks:     map[string][]model.Block{},
	}
}

func TestCrossOIDCProvider_NoProvider(t *testing.T) {
	r := &CrossOIDCProviderRule{}
	resources := []model.TerraformResource{
		makeEKSRes("aws_eks_cluster", "main", map[string]interface{}{"name": "my-cluster"}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EKS-008", findings[0].RuleID)
}

func TestCrossOIDCProvider_WithMatchingProvider(t *testing.T) {
	r := &CrossOIDCProviderRule{}
	resources := []model.TerraformResource{
		makeEKSRes("aws_eks_cluster", "main", map[string]interface{}{"name": "my-cluster"}),
		makeEKSRes("aws_iam_openid_connect_provider", "eks_oidc", map[string]interface{}{
			"url": "https://oidc.eks.us-east-1.amazonaws.com/id/ABC123",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossOIDCProvider_NoClusters(t *testing.T) {
	r := &CrossOIDCProviderRule{}
	findings := r.EvaluateAll(nil)
	assert.Empty(t, findings)
}

func TestCrossOIDCProvider_ProviderNotMatchingCluster(t *testing.T) {
	r := &CrossOIDCProviderRule{}
	resources := []model.TerraformResource{
		makeEKSRes("aws_eks_cluster", "main", map[string]interface{}{"name": "my-cluster"}),
		makeEKSRes("aws_iam_openid_connect_provider", "other_oidc", map[string]interface{}{
			"url": "https://cognito-identity.amazonaws.com",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EKS-008", findings[0].RuleID)
}

// --- EKS-009: Cross Compute ---

func TestCrossCompute_NoNodeGroup(t *testing.T) {
	r := &CrossComputeRule{}
	resources := []model.TerraformResource{
		makeEKSRes("aws_eks_cluster", "main", map[string]interface{}{"name": "my-cluster"}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EKS-009", findings[0].RuleID)
}

func TestCrossCompute_WithNodeGroup(t *testing.T) {
	r := &CrossComputeRule{}
	resources := []model.TerraformResource{
		makeEKSRes("aws_eks_cluster", "main", map[string]interface{}{"name": "my-cluster"}),
		makeEKSRes("aws_eks_node_group", "workers", map[string]interface{}{
			"cluster_name": "my-cluster",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossCompute_WithFargateProfile(t *testing.T) {
	r := &CrossComputeRule{}
	resources := []model.TerraformResource{
		makeEKSRes("aws_eks_cluster", "main", map[string]interface{}{"name": "my-cluster"}),
		makeEKSRes("aws_eks_fargate_profile", "default", map[string]interface{}{
			"cluster_name": "my-cluster",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossCompute_MultipleClusters_OneUncovered(t *testing.T) {
	r := &CrossComputeRule{}
	resources := []model.TerraformResource{
		makeEKSRes("aws_eks_cluster", "cluster1", map[string]interface{}{"name": "cluster-1"}),
		makeEKSRes("aws_eks_cluster", "cluster2", map[string]interface{}{"name": "cluster-2"}),
		makeEKSRes("aws_eks_node_group", "workers", map[string]interface{}{"cluster_name": "cluster-1"}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Contains(t, findings[0].Resource, "cluster2")
}
