package acm

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

// --- ACM-001: Validation Method ---

func TestValidationMethod_Email(t *testing.T) {
	r := &ValidationMethodRule{}
	findings := r.Evaluate(res("aws_acm_certificate", "cert", map[string]interface{}{
		"validation_method": "EMAIL",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "ACM-001", findings[0].RuleID)
}

func TestValidationMethod_DNS(t *testing.T) {
	r := &ValidationMethodRule{}
	findings := r.Evaluate(res("aws_acm_certificate", "cert", map[string]interface{}{
		"validation_method": "DNS",
	}))
	assert.Empty(t, findings)
}

func TestValidationMethod_Missing(t *testing.T) {
	r := &ValidationMethodRule{}
	findings := r.Evaluate(res("aws_acm_certificate", "cert", map[string]interface{}{}))
	assert.Len(t, findings, 1)
}

// --- ACM-002: Wildcard Cert ---

func TestWildcardCert_NotWildcard(t *testing.T) {
	r := &WildcardCertRule{}
	findings := r.Evaluate(res("aws_acm_certificate", "cert", map[string]interface{}{
		"domain_name": "api.example.com",
	}))
	assert.Empty(t, findings)
}

func TestWildcardCert_WildcardWithSpecificSANs(t *testing.T) {
	r := &WildcardCertRule{}
	findings := r.Evaluate(res("aws_acm_certificate", "cert", map[string]interface{}{
		"domain_name":               "*.example.com",
		"subject_alternative_names": []interface{}{"api.example.com", "web.example.com"},
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "ACM-002", findings[0].RuleID)
}

func TestWildcardCert_WildcardWithOnlyWildcardSANs(t *testing.T) {
	r := &WildcardCertRule{}
	findings := r.Evaluate(res("aws_acm_certificate", "cert", map[string]interface{}{
		"domain_name":               "*.example.com",
		"subject_alternative_names": []interface{}{"*.example.com"},
	}))
	assert.Empty(t, findings)
}

func TestWildcardCert_WildcardNoSANs(t *testing.T) {
	r := &WildcardCertRule{}
	findings := r.Evaluate(res("aws_acm_certificate", "cert", map[string]interface{}{
		"domain_name": "*.example.com",
	}))
	assert.Empty(t, findings)
}

// --- ACM-003: TLS Policy ---

func TestTLSPolicy_Outdated(t *testing.T) {
	r := &TLSPolicyRule{}
	findings := r.Evaluate(res("aws_lb_listener", "https", map[string]interface{}{
		"protocol":   "HTTPS",
		"ssl_policy": "ELBSecurityPolicy-2016-08",
	}))
	assert.Len(t, findings, 1)
	assert.Equal(t, "ACM-003", findings[0].RuleID)
}

func TestTLSPolicy_Modern(t *testing.T) {
	r := &TLSPolicyRule{}
	findings := r.Evaluate(res("aws_lb_listener", "https", map[string]interface{}{
		"protocol":   "HTTPS",
		"ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
	}))
	assert.Empty(t, findings)
}

func TestTLSPolicy_HTTPNotApplicable(t *testing.T) {
	r := &TLSPolicyRule{}
	findings := r.Evaluate(res("aws_lb_listener", "http", map[string]interface{}{
		"protocol": "HTTP",
	}))
	assert.Empty(t, findings)
}

func TestTLSPolicy_MissingPolicy(t *testing.T) {
	r := &TLSPolicyRule{}
	findings := r.Evaluate(res("aws_lb_listener", "https", map[string]interface{}{
		"protocol": "HTTPS",
	}))
	assert.Len(t, findings, 1)
}
