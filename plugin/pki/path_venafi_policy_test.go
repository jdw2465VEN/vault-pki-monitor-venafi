package pki

import (
	"context"
	"github.com/hashicorp/vault/logical"
	"os"
	"testing"
)

func TestBackend_VenafiPolicyTPP(t *testing.T) {
	rand := randSeq(9)
	domain := "example.com"

	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	// generate root
	rootData := map[string]interface{}{
		"common_name": domain,
		"ttl":         "6h",
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   storage,
		Data:      rootData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to generate root, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	// config urls
	urlsData := map[string]interface{}{
		"issuing_certificates":    "http://127.0.0.1:8200/v1/pki/ca",
		"crl_distribution_points": "http://127.0.0.1:8200/v1/pki/crl",
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/urls",
		Storage:   storage,
		Data:      urlsData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to config urls, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	// Configure Venafi default policy
	policyData := map[string]interface{}{
		"tpp_url":            os.Getenv("TPPURL"),
		"tpp_user":           os.Getenv("TPPUSER"),
		"tpp_password":       os.Getenv("TPPPASSWORD"),
		"zone":               os.Getenv("TPPZONE"),
		"trust_bundle_file":  os.Getenv("TRUST_BUNDLE"),
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "venafi-policy/default",
		Storage:   storage,
		Data:      policyData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to configure venafi policy, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	//TODO: read venafi policy configuration
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "venafi-policy/default",
		Storage:   storage,
	})

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to read venafi policy, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	//TODO: Policy data should be stored and read in json
	policyJSON := resp.Data["venafi_policy"]
	if policyJSON == nil {
		t.Fatalf("Can't read policy data")
	}

	// create a role entry with default policy
	roleData := map[string]interface{}{
		"allowed_domains":    domain,
		"allow_subdomains":   "true",
		"max_ttl":            "4h",
		"allow_bare_domains": true,
		"generate_lease":     true,
		"tpp_url":            os.Getenv("TPPURL"),
		"tpp_user":           os.Getenv("TPPUSER"),
		"tpp_password":       os.Getenv("TPPPASSWORD"),
		"zone":               os.Getenv("TPPZONE"),
		"trust_bundle_file":  os.Getenv("TRUST_BUNDLE"),
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-venafi-policy",
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	// issue particular cert
	singleCN := rand + "-import." + domain
	certData := map[string]interface{}{
		"common_name": singleCN,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/test-import",
		Storage:   storage,
		Data:      certData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue a cert, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}


}

