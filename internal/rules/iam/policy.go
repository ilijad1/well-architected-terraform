package iam

import (
	"encoding/json"
	"strings"
)

// PolicyDocument represents an IAM JSON policy document.
type PolicyDocument struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement"`
}

// PolicyStatement represents a single statement in an IAM policy.
type PolicyStatement struct {
	Sid       string      `json:"Sid,omitempty"`
	Effect    string      `json:"Effect"`
	Action    interface{} `json:"Action"`
	Resource  interface{} `json:"Resource"`
	Principal interface{} `json:"Principal,omitempty"`
	Condition interface{} `json:"Condition,omitempty"`
}

// ParsePolicyJSON parses a JSON policy document string.
// Returns nil with no error if the input is empty or not valid JSON.
func ParsePolicyJSON(jsonStr string) (*PolicyDocument, error) {
	jsonStr = strings.TrimSpace(jsonStr)
	if jsonStr == "" {
		return nil, nil
	}

	var doc PolicyDocument
	if err := json.Unmarshal([]byte(jsonStr), &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// ActionsFromStatement extracts actions as a string slice.
// IAM actions can be a single string or an array of strings.
func ActionsFromStatement(stmt PolicyStatement) []string {
	return toStringSlice(stmt.Action)
}

// ResourcesFromStatement extracts resources as a string slice.
func ResourcesFromStatement(stmt PolicyStatement) []string {
	return toStringSlice(stmt.Resource)
}

// PrincipalsFromStatement extracts AWS principals from a statement.
// Principal can be "*", {"AWS": "arn:..."}, or {"AWS": ["arn:...", ...]}.
func PrincipalsFromStatement(stmt PolicyStatement) []string {
	if stmt.Principal == nil {
		return nil
	}

	switch v := stmt.Principal.(type) {
	case string:
		return []string{v}
	case map[string]interface{}:
		var principals []string
		for _, val := range v {
			principals = append(principals, toStringSlice(val)...)
		}
		return principals
	}
	return nil
}

// HasConditionKey checks if a statement has a specific condition key in any operator.
func HasConditionKey(stmt PolicyStatement, key string) bool {
	condMap, ok := stmt.Condition.(map[string]interface{})
	if !ok {
		return false
	}
	for _, operatorVal := range condMap {
		keys, ok := operatorVal.(map[string]interface{})
		if !ok {
			continue
		}
		for k := range keys {
			if strings.EqualFold(k, key) {
				return true
			}
		}
	}
	return false
}

func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		var result []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// ContainsWildcard returns true if any element is "*".
func ContainsWildcard(items []string) bool {
	for _, item := range items {
		if item == "*" {
			return true
		}
	}
	return false
}

// isCrossAccountPrincipal returns true if a principal ARN references a different account.
// A principal of "*" is always cross-account. ARN format: arn:aws:iam::ACCOUNT_ID:...
func isCrossAccountPrincipal(principal string) bool {
	if principal == "*" {
		return true
	}
	// Principals that contain ":root" from another account
	return strings.Contains(principal, ":root") || strings.HasPrefix(principal, "arn:aws:iam::")
}
