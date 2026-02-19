package sustainability

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func res(resType, name string, attrs map[string]interface{}) model.TerraformResource {
	return model.TerraformResource{
		Type:       resType,
		Name:       name,
		Attributes: attrs,
		Blocks:     map[string][]model.Block{},
	}
}

func resWithBlocks(resType, name string, attrs map[string]interface{}, blocks map[string][]model.Block) model.TerraformResource {
	return model.TerraformResource{
		Type:       resType,
		Name:       name,
		Attributes: attrs,
		Blocks:     blocks,
	}
}

// --- SUS-001: Graviton EC2 ---

func TestGravitonEC2_NonGraviton(t *testing.T) {
	r := &GravitonEC2Rule{}
	findings := r.Evaluate(res("aws_instance", "web", map[string]interface{}{
		"instance_type": "m5.large",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-001", findings[0].RuleID)
}

func TestGravitonEC2_Graviton(t *testing.T) {
	r := &GravitonEC2Rule{}
	findings := r.Evaluate(res("aws_instance", "web", map[string]interface{}{
		"instance_type": "m7g.large",
	}))
	assert.Empty(t, findings)
}

func TestGravitonEC2_GravitonGd(t *testing.T) {
	r := &GravitonEC2Rule{}
	findings := r.Evaluate(res("aws_instance", "web", map[string]interface{}{
		"instance_type": "m7gd.xlarge",
	}))
	assert.Empty(t, findings)
}

func TestGravitonEC2_T4g(t *testing.T) {
	r := &GravitonEC2Rule{}
	findings := r.Evaluate(res("aws_instance", "web", map[string]interface{}{
		"instance_type": "t4g.micro",
	}))
	assert.Empty(t, findings)
}

func TestGravitonEC2_NoInstanceType(t *testing.T) {
	r := &GravitonEC2Rule{}
	findings := r.Evaluate(res("aws_instance", "web", map[string]interface{}{}))
	assert.Empty(t, findings)
}

// --- SUS-002: Graviton RDS ---

func TestGravitonRDS_NonGraviton(t *testing.T) {
	r := &GravitonRDSRule{}
	findings := r.Evaluate(res("aws_db_instance", "db", map[string]interface{}{
		"instance_class": "db.m5.large",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-002", findings[0].RuleID)
}

func TestGravitonRDS_Graviton(t *testing.T) {
	r := &GravitonRDSRule{}
	findings := r.Evaluate(res("aws_db_instance", "db", map[string]interface{}{
		"instance_class": "db.m7g.large",
	}))
	assert.Empty(t, findings)
}

// --- SUS-003: Graviton ElastiCache ---

func TestGravitonElastiCache_NonGraviton(t *testing.T) {
	r := &GravitonElastiCacheRule{}
	findings := r.Evaluate(res("aws_elasticache_replication_group", "cache", map[string]interface{}{
		"node_type": "cache.m5.large",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-003", findings[0].RuleID)
}

func TestGravitonElastiCache_Graviton(t *testing.T) {
	r := &GravitonElastiCacheRule{}
	findings := r.Evaluate(res("aws_elasticache_replication_group", "cache", map[string]interface{}{
		"node_type": "cache.m7g.large",
	}))
	assert.Empty(t, findings)
}

// --- SUS-004: S3 Intelligent Tiering ---

func TestS3IntelligentTiering_NoCoverage(t *testing.T) {
	r := &S3IntelligentTieringRule{}
	resources := []model.TerraformResource{
		res("aws_s3_bucket", "data", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-004", findings[0].RuleID)
}

func TestS3IntelligentTiering_WithTiering(t *testing.T) {
	r := &S3IntelligentTieringRule{}
	resources := []model.TerraformResource{
		res("aws_s3_bucket", "data", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
		res("aws_s3_bucket_intelligent_tiering_configuration", "data_tiering", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

func TestS3IntelligentTiering_WithLifecycle(t *testing.T) {
	r := &S3IntelligentTieringRule{}
	resources := []model.TerraformResource{
		res("aws_s3_bucket", "data", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
		res("aws_s3_bucket_lifecycle_configuration", "data_lc", map[string]interface{}{
			"bucket": "my-data-bucket",
		}),
	}
	findings := r.EvaluateAll(resources)
	assert.Empty(t, findings)
}

// --- SUS-005: Lambda ARM64 ---

func TestLambdaARM_X86(t *testing.T) {
	r := &LambdaARMRule{}
	findings := r.Evaluate(res("aws_lambda_function", "fn", map[string]interface{}{
		"architectures": []interface{}{"x86_64"},
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-005", findings[0].RuleID)
}

func TestLambdaARM_ARM64(t *testing.T) {
	r := &LambdaARMRule{}
	findings := r.Evaluate(res("aws_lambda_function", "fn", map[string]interface{}{
		"architectures": []interface{}{"arm64"},
	}))
	assert.Empty(t, findings)
}

func TestLambdaARM_NoArchitectures(t *testing.T) {
	r := &LambdaARMRule{}
	findings := r.Evaluate(res("aws_lambda_function", "fn", map[string]interface{}{}))
	assert.Len(t, findings, 1) // defaults to x86_64
}

// --- SUS-006: ASG Mixed Instances ---

func TestASGMixedInstances_NoPolicy(t *testing.T) {
	r := &ASGMixedInstancesRule{}
	findings := r.Evaluate(res("aws_autoscaling_group", "asg", map[string]interface{}{}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-006", findings[0].RuleID)
}

func TestASGMixedInstances_WithPolicy(t *testing.T) {
	r := &ASGMixedInstancesRule{}
	findings := r.Evaluate(resWithBlocks("aws_autoscaling_group", "asg",
		map[string]interface{}{},
		map[string][]model.Block{
			"mixed_instances_policy": {{Type: "mixed_instances_policy", Attributes: map[string]interface{}{}}},
		},
	))
	assert.Empty(t, findings)
}

// --- SUS-007: EBS gp3 ---

func TestEBSGP3_GP2(t *testing.T) {
	r := &EBSGP3Rule{}
	findings := r.Evaluate(res("aws_ebs_volume", "vol", map[string]interface{}{
		"type": "gp2",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-007", findings[0].RuleID)
}

func TestEBSGP3_GP3(t *testing.T) {
	r := &EBSGP3Rule{}
	findings := r.Evaluate(res("aws_ebs_volume", "vol", map[string]interface{}{
		"type": "gp3",
	}))
	assert.Empty(t, findings)
}

// --- SUS-008: RDS Storage Autoscaling ---

func TestRDSStorageAutoscaling_Missing(t *testing.T) {
	r := &RDSStorageAutoscalingRule{}
	findings := r.Evaluate(res("aws_db_instance", "db", map[string]interface{}{
		"allocated_storage": float64(100),
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-008", findings[0].RuleID)
}

func TestRDSStorageAutoscaling_Present(t *testing.T) {
	r := &RDSStorageAutoscalingRule{}
	findings := r.Evaluate(res("aws_db_instance", "db", map[string]interface{}{
		"allocated_storage":     float64(100),
		"max_allocated_storage": float64(500),
	}))
	assert.Empty(t, findings)
}

// --- SUS-009: Graviton EKS ---

func TestGravitonEKS_NonGraviton(t *testing.T) {
	r := &GravitonEKSRule{}
	findings := r.Evaluate(res("aws_eks_node_group", "workers", map[string]interface{}{
		"instance_types": []interface{}{"m5.large"},
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-009", findings[0].RuleID)
}

func TestGravitonEKS_Graviton(t *testing.T) {
	r := &GravitonEKSRule{}
	findings := r.Evaluate(res("aws_eks_node_group", "workers", map[string]interface{}{
		"instance_types": []interface{}{"m7g.large"},
	}))
	assert.Empty(t, findings)
}

func TestGravitonEKS_MixedTypes_OneGraviton(t *testing.T) {
	r := &GravitonEKSRule{}
	findings := r.Evaluate(res("aws_eks_node_group", "workers", map[string]interface{}{
		"instance_types": []interface{}{"m5.large", "m7g.large"},
	}))
	assert.Empty(t, findings)
}

func TestGravitonEKS_NoInstanceTypes(t *testing.T) {
	r := &GravitonEKSRule{}
	findings := r.Evaluate(res("aws_eks_node_group", "workers", map[string]interface{}{}))
	assert.Empty(t, findings)
}

// --- SUS-010: DynamoDB TTL ---

func TestDynamoDBTTL_Enabled(t *testing.T) {
	r := &DynamoDBTTLRule{}
	findings := r.Evaluate(resWithBlocks("aws_dynamodb_table", "tbl", map[string]interface{}{},
		map[string][]model.Block{
			"ttl": {{Type: "ttl", Attributes: map[string]interface{}{"enabled": true, "attribute_name": "expires_at"}}},
		},
	))
	assert.Empty(t, findings)
}

func TestDynamoDBTTL_Disabled(t *testing.T) {
	r := &DynamoDBTTLRule{}
	findings := r.Evaluate(resWithBlocks("aws_dynamodb_table", "tbl", map[string]interface{}{},
		map[string][]model.Block{
			"ttl": {{Type: "ttl", Attributes: map[string]interface{}{"enabled": false}}},
		},
	))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-010", findings[0].RuleID)
}

func TestDynamoDBTTL_NoBlock(t *testing.T) {
	r := &DynamoDBTTLRule{}
	findings := r.Evaluate(res("aws_dynamodb_table", "tbl", map[string]interface{}{}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-010", findings[0].RuleID)
}

// --- SUS-011: ECS Fargate ---

func TestECSFargate_FargateCompatible(t *testing.T) {
	r := &ECSFargateRule{}
	findings := r.Evaluate(res("aws_ecs_task_definition", "task", map[string]interface{}{
		"requires_compatibilities": []interface{}{"FARGATE"},
	}))
	assert.Empty(t, findings)
}

func TestECSFargate_EC2Only(t *testing.T) {
	r := &ECSFargateRule{}
	findings := r.Evaluate(res("aws_ecs_task_definition", "task", map[string]interface{}{
		"requires_compatibilities": []interface{}{"EC2"},
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-011", findings[0].RuleID)
}

func TestECSFargate_NoCompatibilities(t *testing.T) {
	r := &ECSFargateRule{}
	findings := r.Evaluate(res("aws_ecs_task_definition", "task", map[string]interface{}{}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-011", findings[0].RuleID)
}

// --- SUS-012: Aurora Serverless v2 ---

func TestRDSServerlessV2_AuroraWithScaling(t *testing.T) {
	r := &RDSServerlessV2Rule{}
	findings := r.Evaluate(resWithBlocks("aws_rds_cluster", "aurora", map[string]interface{}{
		"engine": "aurora-postgresql",
	}, map[string][]model.Block{
		"serverless_v2_scaling_configuration": {{
			Type:       "serverless_v2_scaling_configuration",
			Attributes: map[string]interface{}{"min_capacity": float64(0.5), "max_capacity": float64(16)},
		}},
	}))
	assert.Empty(t, findings)
}

func TestRDSServerlessV2_AuroraWithoutScaling(t *testing.T) {
	r := &RDSServerlessV2Rule{}
	findings := r.Evaluate(res("aws_rds_cluster", "aurora", map[string]interface{}{
		"engine": "aurora-postgresql",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-012", findings[0].RuleID)
}

func TestRDSServerlessV2_NonAurora(t *testing.T) {
	r := &RDSServerlessV2Rule{}
	findings := r.Evaluate(res("aws_rds_cluster", "mysql", map[string]interface{}{
		"engine": "mysql",
	}))
	assert.Empty(t, findings)
}

// --- SUS-013: Kinesis On-Demand ---

func TestKinesisOnDemand_OnDemand(t *testing.T) {
	r := &KinesisOnDemandRule{}
	findings := r.Evaluate(resWithBlocks("aws_kinesis_stream", "stream", map[string]interface{}{},
		map[string][]model.Block{
			"stream_mode_details": {{
				Type:       "stream_mode_details",
				Attributes: map[string]interface{}{"stream_mode": "ON_DEMAND"},
			}},
		},
	))
	assert.Empty(t, findings)
}

func TestKinesisOnDemand_Provisioned(t *testing.T) {
	r := &KinesisOnDemandRule{}
	findings := r.Evaluate(resWithBlocks("aws_kinesis_stream", "stream", map[string]interface{}{},
		map[string][]model.Block{
			"stream_mode_details": {{
				Type:       "stream_mode_details",
				Attributes: map[string]interface{}{"stream_mode": "PROVISIONED"},
			}},
		},
	))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-013", findings[0].RuleID)
}

func TestKinesisOnDemand_NoStreamModeDetails(t *testing.T) {
	r := &KinesisOnDemandRule{}
	findings := r.Evaluate(res("aws_kinesis_stream", "stream", map[string]interface{}{}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-013", findings[0].RuleID)
}

// --- SUS-014: Redshift RA3 ---

func TestRedshiftRA3_RA3Node(t *testing.T) {
	r := &RedshiftRA3Rule{}
	findings := r.Evaluate(res("aws_redshift_cluster", "dw", map[string]interface{}{
		"node_type": "ra3.xlplus",
	}))
	assert.Empty(t, findings)
}

func TestRedshiftRA3_OldGenNode(t *testing.T) {
	r := &RedshiftRA3Rule{}
	findings := r.Evaluate(res("aws_redshift_cluster", "dw", map[string]interface{}{
		"node_type": "dc2.large",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-014", findings[0].RuleID)
}

func TestRedshiftRA3_NoNodeType(t *testing.T) {
	r := &RedshiftRA3Rule{}
	findings := r.Evaluate(res("aws_redshift_cluster", "dw", map[string]interface{}{}))
	assert.Empty(t, findings)
}

// --- SUS-015: OpenSearch UltraWarm ---

func TestOpenSearchUltraWarm_Enabled(t *testing.T) {
	r := &OpenSearchUltraWarmRule{}
	findings := r.Evaluate(resWithBlocks("aws_opensearch_domain", "search", map[string]interface{}{},
		map[string][]model.Block{
			"cluster_config": {{
				Type:       "cluster_config",
				Attributes: map[string]interface{}{"warm_enabled": true, "warm_count": 2, "warm_type": "ultrawarm1.medium.search"},
			}},
		},
	))
	assert.Empty(t, findings)
}

func TestOpenSearchUltraWarm_Disabled(t *testing.T) {
	r := &OpenSearchUltraWarmRule{}
	findings := r.Evaluate(resWithBlocks("aws_opensearch_domain", "search", map[string]interface{}{},
		map[string][]model.Block{
			"cluster_config": {{
				Type:       "cluster_config",
				Attributes: map[string]interface{}{"warm_enabled": false},
			}},
		},
	))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-015", findings[0].RuleID)
}

func TestOpenSearchUltraWarm_NoClusterConfig(t *testing.T) {
	r := &OpenSearchUltraWarmRule{}
	findings := r.Evaluate(res("aws_opensearch_domain", "search", map[string]interface{}{}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-015", findings[0].RuleID)
}

// --- SUS-016: MSK gp3 ---

func TestMSKgp3_GP3(t *testing.T) {
	r := &MSKgp3Rule{}
	findings := r.Evaluate(resWithBlocks("aws_msk_cluster", "kafka", map[string]interface{}{},
		map[string][]model.Block{
			"broker_node_group_info": {{
				Type:       "broker_node_group_info",
				Attributes: map[string]interface{}{},
				Blocks: map[string][]model.Block{
					"storage_info": {{
						Type:       "storage_info",
						Attributes: map[string]interface{}{},
						Blocks: map[string][]model.Block{
							"ebs_storage_info": {{
								Type:       "ebs_storage_info",
								Attributes: map[string]interface{}{"volume_type": "gp3"},
							}},
						},
					}},
				},
			}},
		},
	))
	assert.Empty(t, findings)
}

func TestMSKgp3_GP2(t *testing.T) {
	r := &MSKgp3Rule{}
	findings := r.Evaluate(resWithBlocks("aws_msk_cluster", "kafka", map[string]interface{}{},
		map[string][]model.Block{
			"broker_node_group_info": {{
				Type:       "broker_node_group_info",
				Attributes: map[string]interface{}{},
				Blocks: map[string][]model.Block{
					"storage_info": {{
						Type:       "storage_info",
						Attributes: map[string]interface{}{},
						Blocks: map[string][]model.Block{
							"ebs_storage_info": {{
								Type:       "ebs_storage_info",
								Attributes: map[string]interface{}{"volume_type": "gp2"},
							}},
						},
					}},
				},
			}},
		},
	))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-016", findings[0].RuleID)
}

func TestMSKgp3_NoBrokerNodeGroup(t *testing.T) {
	r := &MSKgp3Rule{}
	findings := r.Evaluate(res("aws_msk_cluster", "kafka", map[string]interface{}{}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-016", findings[0].RuleID)
}

// --- SUS-017: DocumentDB Graviton ---

func TestGravitonDocDB_Graviton(t *testing.T) {
	r := &GravitonDocDBRule{}
	findings := r.Evaluate(res("aws_docdb_cluster_instance", "inst", map[string]interface{}{
		"instance_class": "db.t4g.medium",
	}))
	assert.Empty(t, findings)
}

func TestGravitonDocDB_NonGraviton(t *testing.T) {
	r := &GravitonDocDBRule{}
	findings := r.Evaluate(res("aws_docdb_cluster_instance", "inst", map[string]interface{}{
		"instance_class": "db.t3.medium",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SUS-017", findings[0].RuleID)
}

func TestGravitonDocDB_R6g(t *testing.T) {
	r := &GravitonDocDBRule{}
	findings := r.Evaluate(res("aws_docdb_cluster_instance", "inst", map[string]interface{}{
		"instance_class": "db.r6g.large",
	}))
	assert.Empty(t, findings)
}

func TestGravitonDocDB_NoInstanceClass(t *testing.T) {
	r := &GravitonDocDBRule{}
	findings := r.Evaluate(res("aws_docdb_cluster_instance", "inst", map[string]interface{}{}))
	assert.Empty(t, findings)
}
