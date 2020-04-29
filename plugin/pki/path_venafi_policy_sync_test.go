package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"os"
	"testing"
	"time"
)

var policyTPPData = map[string]interface{}{
	"tpp_url":           os.Getenv("TPP_URL"),
	"tpp_user":          os.Getenv("TPP_USER"),
	"tpp_password":      os.Getenv("TPP_PASSWORD"),
	"zone":              os.Getenv("TPP_ZONE"),
	"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
}

var policyTPPData2 = map[string]interface{}{
	"tpp_url":           os.Getenv("TPP_URL"),
	"tpp_user":          os.Getenv("TPP_USER"),
	"tpp_password":      os.Getenv("TPP_PASSWORD"),
	"zone":              os.Getenv("TPP_ZONE2"),
	"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
}

var policyCloudData = map[string]interface{}{
	"apikey":    os.Getenv("CLOUD_APIKEY"),
	"cloud_url": os.Getenv("CLOUD_URL"),
	"zone":      os.Getenv("CLOUD_ZONE_RESTRICTED"),
}

var wantTPPRoleEntry = roleEntry{
	Organization:   []string{"Venafi Inc."},
	OU:             []string{"Integrations"},
	Locality:       []string{"Salt Lake"},
	Province:       []string{"Utah"},
	Country:        []string{"US"},
	AllowedDomains: []string{},
	KeyUsage:       []string{"CertSign"},
}

var wantCloudRoleEntry = roleEntry{
	Organization:   []string{"Venafi Inc."},
	OU:             []string{"Integrations"},
	Locality:       []string{"Salt Lake"},
	Province:       []string{"Utah"},
	Country:        []string{"US"},
	AllowedDomains: []string{},
	KeyUsage:       []string{"CertSign"},
}

var wantTPPRoleEntry2 = roleEntry{
	Organization:   []string{"Venafi2"},
	OU:             []string{"Integrations2"},
	Locality:       []string{"Default"},
	Province:       []string{"Utah2"},
	Country:        []string{"FR"},
	AllowedDomains: []string{},
	KeyUsage:       []string{"CertSign"},
}

var wantTPPRoleEntryNoSync = roleEntry{
	Organization:   []string{"Default"},
	OU:             []string{"Default"},
	Locality:       []string{"Default"},
	Province:       []string{"Default"},
	Country:        []string{"Default"},
	AllowedDomains: []string{"example.com"},
	KeyUsage:       []string{"CertSign"},
}

var roleData = map[string]interface{}{
	"organization":       "Default",
	"ou":                 "Default",
	"locality":           "Default",
	"province":           "Default",
	"country":            "Default",
	"allowed_domains":    "example.com",
	"allow_subdomains":   "true",
	"max_ttl":            "4h",
	"key_usage":          "CertSign",
	"allow_bare_domains": true,
	"generate_lease":     true,
}

func TestSyncRoleWithTPPPolicy(t *testing.T) {
	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	testRoleName := "test-venafi-role"
	config.StorageView = storage
	policy := copyMap(policyTPPData2)
	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + testRoleName,
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	//write TPP policy
	policy[policyFieldDefaultsRoles] = testRoleName
	writePolicy(b, storage, policy, t, defaultVenafiPolicyName)

	ctx := context.Background()
	err = b.syncPolicyEnforcementAndRoleDefaults(config)
	if err != nil {
		t.Fatal(err)
	}

	roleEntryData, err := b.getPKIRoleEntry(ctx, storage, testRoleName)

	if err != nil {
		t.Fatal(err)
	}

	if roleEntryData == nil {
		t.Fatal("role entry should not be nil")
	}

	t.Log("Checking modified role entry")
	checkRoleEntry(t, *roleEntryData, wantTPPRoleEntry2)
	b.taskStorage.stop = true
}

func TestIntegrationSyncRoleWithPolicy(t *testing.T) {
	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	testRoleName := "test-venafi-role"
	config.StorageView = storage
	policy := copyMap(policyTPPData)

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	//write TPP policy
	writePolicy(b, storage, policy, t, defaultVenafiPolicyName)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + testRoleName,
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	policy[policyFieldDefaultsRoles] = testRoleName
	writePolicy(b, storage, policy, t, defaultVenafiPolicyName)

	ctx := context.Background()

	t.Log("Sleeping to wait while scheduler execute sync task")
	time.Sleep(25 * time.Second)

	t.Log("Checking role entry")
	roleEntryData, err := b.getPKIRoleEntry(ctx, storage, testRoleName)

	if err != nil {
		t.Fatal(err)
	}

	if roleEntryData == nil {
		t.Fatal("role entry should not be nil")
	}

	t.Log("Checking modified role entry")
	checkRoleEntry(t, *roleEntryData, wantTPPRoleEntry)
	b.taskStorage.stop = true
}

func TestSyncRoleWithCloudPolicy(t *testing.T) {
	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	testRoleName := "test-venafi-role"
	config.StorageView = storage
	policy := copyMap(policyCloudData)

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	//write TPP policy
	writePolicy(b, storage, policy, t, defaultVenafiPolicyName)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + testRoleName,
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	policy[policyFieldDefaultsRoles] = testRoleName
	writePolicy(b, storage, policy, t, defaultVenafiPolicyName)

	ctx := context.Background()
	err = b.syncPolicyEnforcementAndRoleDefaults(config)
	if err != nil {
		t.Fatal(err)
	}

	roleEntryData, err := b.getPKIRoleEntry(ctx, storage, testRoleName)

	if err != nil {
		t.Fatal(err)
	}

	if roleEntryData == nil {
		t.Fatal("role entry should not be nil")
	}

	t.Log("Checking modified role entry")
	checkRoleEntry(t, *roleEntryData, wantCloudRoleEntry)
	b.taskStorage.stop = true
}

func TestSyncMultipleRolesWithTPPPolicy(t *testing.T) {
	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	testRoleName := "test-venafi-role"
	config.StorageView = storage

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Setting up first role")

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + testRoleName,
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Setting up second role")
	writePolicy(b, storage, policyCloudData, t, "cloud-policy")

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + testRoleName + "-second",
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Setting up third role without sync")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + testRoleName + "-third",
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Setting up fourth role")

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + testRoleName + "-fourth",
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Setting up policy")

	policy := copyMap(policyTPPData)
	policy[policyFieldDefaultsRoles] = fmt.Sprintf("%s,%s", testRoleName, testRoleName+"-second")
	writePolicy(b, storage, policy, t, "tpp-policy")

	policy2 := copyMap(policyTPPData2)
	policy2[policyFieldDefaultsRoles] = testRoleName + "-fourth"
	writePolicy(b, storage, policy2, t, "tpp2-policy")

	ctx := context.Background()
	err = b.syncPolicyEnforcementAndRoleDefaults(config)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Checking data for the first role")
	roleEntryData, err := b.getPKIRoleEntry(ctx, storage, testRoleName)

	if err != nil {
		t.Fatal(err)
	}

	if roleEntryData == nil {
		t.Fatal("role entry should not be nil")
	}

	checkRoleEntry(t, *roleEntryData, wantTPPRoleEntry)

	t.Log("Checking data for the second role")
	roleEntryData, err = b.getPKIRoleEntry(ctx, storage, testRoleName+"-second")

	if err != nil {
		t.Fatal(err)
	}

	if roleEntryData == nil {
		t.Fatal("role entry should not be nil")
	}

	checkRoleEntry(t, *roleEntryData, wantCloudRoleEntry)

	t.Log("Checking data for the third role")
	roleEntryData, err = b.getPKIRoleEntry(ctx, storage, testRoleName+"-third")

	if err != nil {
		t.Fatal(err)
	}

	if roleEntryData == nil {
		t.Fatal("role entry should not be nil")
	}

	checkRoleEntry(t, *roleEntryData, wantTPPRoleEntryNoSync)

	t.Log("Checking data for the fourth role")
	roleEntryData, err = b.getPKIRoleEntry(ctx, storage, testRoleName+"-fourth")

	if err != nil {
		t.Fatal(err)
	}

	if roleEntryData == nil {
		t.Fatal("role entry should not be nil")
	}

	checkRoleEntry(t, *roleEntryData, wantTPPRoleEntry2)

	//	List roles with sync
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      venafiSyncPolicyListPath,
		Storage:   storage,
	})

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to list roles, %#v", resp)
	}

	if err != nil {
		t.Fatal(err)
	}

	if resp.Data["keys"] == nil {
		t.Fatalf("Expected there will be roles in the keys list")
	}
	b.taskStorage.stop = true
}

func Test_backend_getPKIRoleEntry(t *testing.T) {
	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-venafi-role",
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	entry, err := b.getPKIRoleEntry(ctx, storage, "test-venafi-role")
	if entry == nil {
		t.Fatal("role entry should not be nil")
	}

	tests := []struct {
		name string
		have string
		want string
	}{
		{"check org", roleData["organization"].(string), entry.Organization[0]},
		{"check ou", roleData["ou"].(string), entry.OU[0]},
		{"check locality", roleData["locality"].(string), entry.Locality[0]},
		{"check province", roleData["province"].(string), entry.Province[0]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.have != tt.want {
				t.Fatalf("%s doesn't match %s", tt.have, tt.want)
			}
		})
	}
	b.taskStorage.stop = true
}

func Test_backend_getVenafiPolicyParams(t *testing.T) {
	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	//write TPP policy
	ctx := context.Background()

	writePolicy(b, storage, policyTPPData, t, defaultVenafiPolicyName)
	venafiPolicyEntry, err := b.getVenafiPolicyParams(ctx, storage, defaultVenafiPolicyName, policyTPPData["zone"].(string))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		have string
		want string
	}{
		{"Check policy Org", wantTPPRoleEntry.Organization[0], venafiPolicyEntry.Organization[0]},
		{"Check policy OU", wantTPPRoleEntry.OU[0], venafiPolicyEntry.OU[0]},
		{"Check policy locality", wantTPPRoleEntry.Locality[0], venafiPolicyEntry.Locality[0]},
		{"Check policy Country", wantTPPRoleEntry.Country[0], venafiPolicyEntry.Country[0]},
		{"Check policy province", wantTPPRoleEntry.Province[0], venafiPolicyEntry.Province[0]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.have != tt.want {
				t.Fatalf("%s doesn't match %s", tt.have, tt.want)
			}
		})
	}
	b.taskStorage.stop = true
}

func Test_canDoRefresh(t *testing.T) {
	type args struct {
		LastPolicyUpdateTime int64
		AutoRefreshInterval  int64
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"not updated yet", args{LastPolicyUpdateTime: 0, AutoRefreshInterval: 10}, true},
		{"just updated", args{LastPolicyUpdateTime: time.Now().Unix(), AutoRefreshInterval: 10}, false},
		{"updated 9 sec ago", args{LastPolicyUpdateTime: time.Now().Unix() - int64(9), AutoRefreshInterval: 10}, false},
		{"updated 11 sec ago", args{LastPolicyUpdateTime: time.Now().Unix() - int64(11), AutoRefreshInterval: 10}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canDoRefresh(tt.args.LastPolicyUpdateTime, tt.args.AutoRefreshInterval); got != tt.want {
				t.Errorf("canDoRefresh() = %v, want %v", got, tt.want)
			}
		})
	}
}
