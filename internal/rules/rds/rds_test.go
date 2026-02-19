package rds

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/ilijad1/well-architected-terraform/internal/parser"
)

func loadResources(t *testing.T, file string) []model.TerraformResource {
	t.Helper()
	p := parser.New()
	resources, err := p.ParseFile(file)
	require.NoError(t, err)
	return resources
}

func findDB(t *testing.T, resources []model.TerraformResource, name string) model.TerraformResource {
	t.Helper()
	for _, r := range resources {
		if r.Type == "aws_db_instance" && r.Name == name {
			return r
		}
	}
	t.Fatalf("aws_db_instance.%s not found", name)
	return model.TerraformResource{}
}

func TestStorageEncryption_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/bad.tf")
	db := findDB(t, resources, "insecure")

	rule := &StorageEncryption{}
	findings := rule.Evaluate(db)
	assert.Len(t, findings, 1)
	assert.Equal(t, "RDS-001", findings[0].RuleID)
}

func TestStorageEncryption_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/good.tf")
	db := findDB(t, resources, "secure")

	rule := &StorageEncryption{}
	findings := rule.Evaluate(db)
	assert.Empty(t, findings)
}

func TestPublicAccess_Public(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/bad.tf")
	db := findDB(t, resources, "insecure")

	rule := &PublicAccess{}
	findings := rule.Evaluate(db)
	assert.Len(t, findings, 1)
	assert.Equal(t, "RDS-002", findings[0].RuleID)
	assert.Equal(t, model.SeverityCritical, findings[0].Severity)
}

func TestPublicAccess_Private(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/good.tf")
	db := findDB(t, resources, "secure")

	rule := &PublicAccess{}
	findings := rule.Evaluate(db)
	assert.Empty(t, findings)
}

func TestMultiAZ_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/bad.tf")
	db := findDB(t, resources, "insecure")

	rule := &MultiAZ{}
	findings := rule.Evaluate(db)
	assert.Len(t, findings, 1)
	assert.Equal(t, "RDS-003", findings[0].RuleID)
}

func TestMultiAZ_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/good.tf")
	db := findDB(t, resources, "secure")

	rule := &MultiAZ{}
	findings := rule.Evaluate(db)
	assert.Empty(t, findings)
}

func TestBackupRetention_Zero(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/bad.tf")
	db := findDB(t, resources, "insecure")

	rule := &BackupRetention{}
	findings := rule.Evaluate(db)
	assert.Len(t, findings, 1)
	assert.Equal(t, "RDS-004", findings[0].RuleID)
}

func TestBackupRetention_Configured(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/good.tf")
	db := findDB(t, resources, "secure")

	rule := &BackupRetention{}
	findings := rule.Evaluate(db)
	assert.Empty(t, findings)
}

func TestInstanceGeneration_OldGen(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/bad.tf")
	db := findDB(t, resources, "insecure")

	rule := &InstanceGeneration{}
	findings := rule.Evaluate(db)
	assert.Len(t, findings, 1)
	assert.Contains(t, findings[0].Description, "db.m4.large")
}

func TestInstanceGeneration_CurrentGen(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/good.tf")
	db := findDB(t, resources, "secure")

	rule := &InstanceGeneration{}
	findings := rule.Evaluate(db)
	assert.Empty(t, findings)
}

func TestInstanceTags_NoTags(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/bad.tf")
	db := findDB(t, resources, "insecure")

	rule := &InstanceTags{}
	findings := rule.Evaluate(db)
	assert.Len(t, findings, 1)
	assert.Equal(t, "RDS-006", findings[0].RuleID)
}

func TestInstanceTags_WithTags(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/good.tf")
	db := findDB(t, resources, "secure")

	rule := &InstanceTags{}
	findings := rule.Evaluate(db)
	assert.Empty(t, findings)
}

func findCluster(t *testing.T, resources []model.TerraformResource, name string) model.TerraformResource {
	t.Helper()
	for _, r := range resources {
		if r.Type == "aws_rds_cluster" && r.Name == name {
			return r
		}
	}
	t.Fatalf("aws_rds_cluster.%s not found", name)
	return model.TerraformResource{}
}

func TestEnhancedMonitoring_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/bad.tf")
	db := findDB(t, resources, "no_enhanced_monitoring")
	findings := (&EnhancedMonitoring{}).Evaluate(db)
	assert.Len(t, findings, 1)
	assert.Equal(t, "RDS-011", findings[0].RuleID)
}

func TestEnhancedMonitoring_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/good.tf")
	db := findDB(t, resources, "enhanced_monitoring")
	findings := (&EnhancedMonitoring{}).Evaluate(db)
	assert.Empty(t, findings)
}

func TestDeletionProtection_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/bad.tf")
	db := findDB(t, resources, "insecure")
	findings := (&DeletionProtection{}).Evaluate(db)
	assert.Len(t, findings, 1)
	assert.Equal(t, "RDS-012", findings[0].RuleID)
}

func TestDeletionProtection_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/good.tf")
	db := findDB(t, resources, "enhanced_monitoring")
	findings := (&DeletionProtection{}).Evaluate(db)
	assert.Empty(t, findings)
}

func TestClusterDeletionProtection_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/bad.tf")
	cluster := findCluster(t, resources, "insecure")
	findings := (&ClusterDeletionProtection{}).Evaluate(cluster)
	assert.Len(t, findings, 1)
	assert.Equal(t, "RDS-013", findings[0].RuleID)
}

func TestClusterDeletionProtection_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/good.tf")
	cluster := findCluster(t, resources, "secure")
	findings := (&ClusterDeletionProtection{}).Evaluate(cluster)
	assert.Empty(t, findings)
}

func TestClusterIAMAuth_Disabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/bad.tf")
	cluster := findCluster(t, resources, "insecure")
	findings := (&ClusterIAMAuth{}).Evaluate(cluster)
	assert.Len(t, findings, 1)
	assert.Equal(t, "RDS-014", findings[0].RuleID)
}

func TestClusterIAMAuth_Enabled(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/good.tf")
	cluster := findCluster(t, resources, "secure")
	findings := (&ClusterIAMAuth{}).Evaluate(cluster)
	assert.Empty(t, findings)
}

func TestDefaultAdmin_DefaultUsername(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/bad.tf")
	db := findDB(t, resources, "default_admin")
	findings := (&DefaultAdmin{}).Evaluate(db)
	assert.Len(t, findings, 1)
	assert.Equal(t, "RDS-015", findings[0].RuleID)
}

func TestDefaultAdmin_CustomUsername(t *testing.T) {
	resources := loadResources(t, "../../../testdata/rds/bad.tf")
	db := findDB(t, resources, "no_enhanced_monitoring")
	findings := (&DefaultAdmin{}).Evaluate(db)
	assert.Empty(t, findings)
}

// --- RDS-016: Cross Event Subscription ---

func makeRDSRes(resType, name string, attrs map[string]interface{}) model.TerraformResource {
	return model.TerraformResource{
		Type:       resType,
		Name:       name,
		Attributes: attrs,
		Blocks:     map[string][]model.Block{},
	}
}

func TestCrossEventSubscription_NoSubscription(t *testing.T) {
	r := &CrossEventSubscriptionRule{}
	resources := []model.TerraformResource{
		makeRDSRes("aws_db_instance", "primary", map[string]interface{}{}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "RDS-016", findings[0].RuleID)
}

func TestCrossEventSubscription_WithFailureSubscription(t *testing.T) {
	r := &CrossEventSubscriptionRule{}
	resources := []model.TerraformResource{
		makeRDSRes("aws_db_instance", "primary", map[string]interface{}{}),
		makeRDSRes("aws_db_event_subscription", "alerts", map[string]interface{}{
			"event_categories": []interface{}{"failure", "maintenance"},
			"sns_topic_arn":    "arn:aws:sns:us-east-1:123456789012:db-alerts",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossEventSubscription_SubscriptionAllEvents(t *testing.T) {
	r := &CrossEventSubscriptionRule{}
	resources := []model.TerraformResource{
		makeRDSRes("aws_db_instance", "primary", map[string]interface{}{}),
		makeRDSRes("aws_db_event_subscription", "all_events", map[string]interface{}{
			"sns_topic_arn": "arn:aws:sns:us-east-1:123456789012:db-alerts",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestCrossEventSubscription_NoRDSResources(t *testing.T) {
	r := &CrossEventSubscriptionRule{}
	findings := r.EvaluateAll(nil)
	assert.Empty(t, findings)
}
