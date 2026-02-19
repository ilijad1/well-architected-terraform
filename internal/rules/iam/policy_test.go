package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePolicyJSON_Valid(t *testing.T) {
	doc, err := ParsePolicyJSON(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`)
	require.NoError(t, err)
	require.NotNil(t, doc)
	assert.Len(t, doc.Statement, 1)
	assert.Equal(t, "Allow", doc.Statement[0].Effect)
}

func TestParsePolicyJSON_EmptyString(t *testing.T) {
	doc, err := ParsePolicyJSON("")
	assert.NoError(t, err)
	assert.Nil(t, doc)
}

func TestParsePolicyJSON_Invalid(t *testing.T) {
	_, err := ParsePolicyJSON("{not json}")
	assert.Error(t, err)
}

func TestActionsFromStatement_String(t *testing.T) {
	stmt := PolicyStatement{Action: "s3:GetObject"}
	actions := ActionsFromStatement(stmt)
	assert.Equal(t, []string{"s3:GetObject"}, actions)
}

func TestActionsFromStatement_Array(t *testing.T) {
	stmt := PolicyStatement{Action: []interface{}{"s3:GetObject", "s3:PutObject"}}
	actions := ActionsFromStatement(stmt)
	assert.Equal(t, []string{"s3:GetObject", "s3:PutObject"}, actions)
}

func TestResourcesFromStatement_Wildcard(t *testing.T) {
	stmt := PolicyStatement{Resource: "*"}
	resources := ResourcesFromStatement(stmt)
	assert.Equal(t, []string{"*"}, resources)
}

func TestPrincipalsFromStatement_Star(t *testing.T) {
	stmt := PolicyStatement{Principal: "*"}
	principals := PrincipalsFromStatement(stmt)
	assert.Equal(t, []string{"*"}, principals)
}

func TestPrincipalsFromStatement_Map(t *testing.T) {
	stmt := PolicyStatement{
		Principal: map[string]interface{}{
			"AWS": "arn:aws:iam::123456789012:root",
		},
	}
	principals := PrincipalsFromStatement(stmt)
	assert.Contains(t, principals, "arn:aws:iam::123456789012:root")
}

func TestPrincipalsFromStatement_MapArray(t *testing.T) {
	stmt := PolicyStatement{
		Principal: map[string]interface{}{
			"AWS": []interface{}{"arn:aws:iam::111111111111:root", "arn:aws:iam::222222222222:root"},
		},
	}
	principals := PrincipalsFromStatement(stmt)
	assert.Len(t, principals, 2)
}

func TestPrincipalsFromStatement_Nil(t *testing.T) {
	stmt := PolicyStatement{}
	principals := PrincipalsFromStatement(stmt)
	assert.Nil(t, principals)
}

func TestHasConditionKey_Present(t *testing.T) {
	stmt := PolicyStatement{
		Condition: map[string]interface{}{
			"StringEquals": map[string]interface{}{
				"sts:ExternalId": "abc123",
			},
		},
	}
	assert.True(t, HasConditionKey(stmt, "sts:ExternalId"))
}

func TestHasConditionKey_Missing(t *testing.T) {
	stmt := PolicyStatement{
		Condition: map[string]interface{}{
			"StringEquals": map[string]interface{}{
				"aws:SourceArn": "some-arn",
			},
		},
	}
	assert.False(t, HasConditionKey(stmt, "sts:ExternalId"))
}

func TestHasConditionKey_NilCondition(t *testing.T) {
	stmt := PolicyStatement{}
	assert.False(t, HasConditionKey(stmt, "sts:ExternalId"))
}

func TestHasConditionKey_CaseInsensitive(t *testing.T) {
	stmt := PolicyStatement{
		Condition: map[string]interface{}{
			"StringEquals": map[string]interface{}{
				"STS:EXTERNALID": "abc123",
			},
		},
	}
	assert.True(t, HasConditionKey(stmt, "sts:ExternalId"))
}

func TestContainsWildcard_True(t *testing.T) {
	assert.True(t, ContainsWildcard([]string{"s3:GetObject", "*"}))
}

func TestContainsWildcard_False(t *testing.T) {
	assert.False(t, ContainsWildcard([]string{"s3:GetObject", "s3:PutObject"}))
}

func TestContainsWildcard_Empty(t *testing.T) {
	assert.False(t, ContainsWildcard(nil))
}
