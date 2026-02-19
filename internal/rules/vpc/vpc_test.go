package vpc

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ilijad1/well-architected-terraform/internal/model"
	"github.com/ilijad1/well-architected-terraform/internal/parser"
)

func TestOpenIngress_OpenSSH(t *testing.T) {
	p := parser.New()
	resources, err := p.ParseFile("../../../testdata/vpc/bad.tf")
	if err != nil {
		t.Fatal(err)
	}

	rule := &OpenIngress{}
	var sshSG model.TerraformResource
	for _, r := range resources {
		if r.Name == "open_ssh" {
			sshSG = r
			break
		}
	}

	findings := rule.Evaluate(sshSG)
	// Should flag SSH (port 22) but NOT HTTPS (port 443)
	assert.Len(t, findings, 1)
	assert.Equal(t, "VPC-001", findings[0].RuleID)
	assert.Contains(t, findings[0].Description, "22")
	assert.Contains(t, findings[0].Description, "SSH")
}

func TestOpenIngress_OpenRDP(t *testing.T) {
	p := parser.New()
	resources, err := p.ParseFile("../../../testdata/vpc/bad.tf")
	if err != nil {
		t.Fatal(err)
	}

	rule := &OpenIngress{}
	var rdpSG model.TerraformResource
	for _, r := range resources {
		if r.Name == "open_rdp" {
			rdpSG = r
			break
		}
	}

	findings := rule.Evaluate(rdpSG)
	assert.Len(t, findings, 1)
	assert.Contains(t, findings[0].Description, "3389")
	assert.Contains(t, findings[0].Description, "RDP")
}

func TestOpenIngress_RestrictedSSH(t *testing.T) {
	p := parser.New()
	resources, err := p.ParseFile("../../../testdata/vpc/good.tf")
	if err != nil {
		t.Fatal(err)
	}

	rule := &OpenIngress{}
	for _, r := range resources {
		if r.Type == "aws_security_group" {
			findings := rule.Evaluate(r)
			assert.Empty(t, findings)
			return
		}
	}
	t.Fatal("no security group found")
}

func loadResources(t *testing.T, file string) []model.TerraformResource {
	t.Helper()
	p := parser.New()
	resources, err := p.ParseFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return resources
}

func findResource(t *testing.T, resources []model.TerraformResource, resType, name string) model.TerraformResource {
	t.Helper()
	for _, r := range resources {
		if r.Type == resType && r.Name == name {
			return r
		}
	}
	t.Fatalf("%s.%s not found", resType, name)
	return model.TerraformResource{}
}

func TestSubnetPublicIP_AutoAssign(t *testing.T) {
	resources := loadResources(t, "../../../testdata/vpc/bad.tf")
	res := findResource(t, resources, "aws_subnet", "public_auto_ip")
	findings := (&SubnetPublicIP{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "VPC-005", findings[0].RuleID)
}

func TestSubnetPublicIP_NoAutoAssign(t *testing.T) {
	resources := loadResources(t, "../../../testdata/vpc/good.tf")
	res := findResource(t, resources, "aws_subnet", "private_no_auto_ip")
	findings := (&SubnetPublicIP{}).Evaluate(res)
	assert.Empty(t, findings)
}

func TestRouteToIGW_DefaultRoute(t *testing.T) {
	resources := loadResources(t, "../../../testdata/vpc/bad.tf")
	res := findResource(t, resources, "aws_route", "default_to_igw")
	findings := (&RouteToIGW{}).Evaluate(res)
	assert.Len(t, findings, 1)
	assert.Equal(t, "VPC-006", findings[0].RuleID)
}

func TestRouteToIGW_NATGateway(t *testing.T) {
	resources := loadResources(t, "../../../testdata/vpc/good.tf")
	res := findResource(t, resources, "aws_route", "private_to_nat")
	findings := (&RouteToIGW{}).Evaluate(res)
	assert.Empty(t, findings)
}
