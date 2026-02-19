package elasticache

import (
	"testing"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/stretchr/testify/assert"
)

// AtRestEncryptionRule Tests
func TestAtRestEncryptionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_elasticache_replication_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"at_rest_encryption_enabled": true,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &AtRestEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestAtRestEncryptionRule_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_elasticache_replication_group",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &AtRestEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EC-001", findings[0].RuleID)
}

func TestAtRestEncryptionRule_Fail_False(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_elasticache_replication_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"at_rest_encryption_enabled": false,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &AtRestEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EC-001", findings[0].RuleID)
}

// TransitEncryptionRule Tests
func TestTransitEncryptionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_elasticache_replication_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"transit_encryption_enabled": true,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &TransitEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestTransitEncryptionRule_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_elasticache_replication_group",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &TransitEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EC-002", findings[0].RuleID)
}

func TestTransitEncryptionRule_Fail_False(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_elasticache_replication_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"transit_encryption_enabled": false,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &TransitEncryptionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EC-002", findings[0].RuleID)
}

// AutomaticFailoverRule Tests
func TestAutomaticFailoverRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_elasticache_replication_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"automatic_failover_enabled": true,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &AutomaticFailoverRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestAutomaticFailoverRule_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_elasticache_replication_group",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &AutomaticFailoverRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EC-003", findings[0].RuleID)
}

func TestAutomaticFailoverRule_Fail_False(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_elasticache_replication_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"automatic_failover_enabled": false,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &AutomaticFailoverRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EC-003", findings[0].RuleID)
}

// MultiNodeRule Tests
func TestMultiNodeRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_elasticache_replication_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"num_cache_clusters": 2,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &MultiNodeRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestMultiNodeRule_Fail_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_elasticache_replication_group",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &MultiNodeRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EC-004", findings[0].RuleID)
}

func TestMultiNodeRule_Fail_One(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_elasticache_replication_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"num_cache_clusters": 1,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &MultiNodeRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EC-004", findings[0].RuleID)
}

// AutoMinorVersionRule Tests
func TestAutoMinorVersionRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_elasticache_replication_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"auto_minor_version_upgrade": true,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &AutoMinorVersionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestAutoMinorVersionRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_elasticache_replication_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"auto_minor_version_upgrade": false,
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &AutoMinorVersionRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EC-005", findings[0].RuleID)
}

func TestAutoMinorVersionRule_Pass_NotSet(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_elasticache_replication_group",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &AutoMinorVersionRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

// TagsRule Tests
func TestTagsRule_Pass(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_elasticache_replication_group",
		Name: "test",
		Attributes: map[string]interface{}{
			"tags": map[string]interface{}{"Environment": "prod"},
		},
		Blocks: map[string][]model.Block{},
	}
	rule := &TagsRule{}
	findings := rule.Evaluate(resource)
	assert.Empty(t, findings)
}

func TestTagsRule_Fail(t *testing.T) {
	resource := model.TerraformResource{
		Type:       "aws_elasticache_replication_group",
		Name:       "test",
		Attributes: map[string]interface{}{},
		Blocks:     map[string][]model.Block{},
	}
	rule := &TagsRule{}
	findings := rule.Evaluate(resource)
	assert.NotEmpty(t, findings)
	assert.Equal(t, "EC-006", findings[0].RuleID)
}

func TestClusterMultiAZ_SingleAZ(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_elasticache_cluster",
		Name: "single_az",
		Attributes: map[string]interface{}{
			"az_mode":        "single-az",
			"num_cache_nodes": float64(1),
		},
		Blocks: map[string][]model.Block{},
	}
	findings := (&ClusterMultiAZ{}).Evaluate(resource)
	assert.Len(t, findings, 1)
	assert.Equal(t, "EC-007", findings[0].RuleID)
}

func TestClusterMultiAZ_CrossAZ(t *testing.T) {
	resource := model.TerraformResource{
		Type: "aws_elasticache_cluster",
		Name: "multi_az",
		Attributes: map[string]interface{}{
			"az_mode":        "cross-az",
			"num_cache_nodes": float64(3),
		},
		Blocks: map[string][]model.Block{},
	}
	findings := (&ClusterMultiAZ{}).Evaluate(resource)
	assert.Empty(t, findings)
}
