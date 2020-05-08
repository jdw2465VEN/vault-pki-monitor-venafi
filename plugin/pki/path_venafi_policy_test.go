package pki

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
	"log"
	"reflect"
	"strings"
	"testing"
)

func TestVenafiPolicyCloud(t *testing.T) {
	domain, policyData := makeVenafiCloudConfig()
	venafiPolicyTests(t, policyData, domain)
}

func TestVenafiPolicyTPP(t *testing.T) {
	domain, policyData := makeVenafiTPPConfig()
	venafiPolicyTests(t, policyData, domain)
}

func TestVenafiPolicyCloudSignBeforeConfigure(t *testing.T) {
	domain, _ := makeVenafiCloudConfig()
	venafiPolicyTestSignBeforeConfigure(t, domain)
}

func TestVenafiPolicyTPPSignBeforeConfigure(t *testing.T) {
	domain, _ := makeVenafiCloudConfig()
	venafiPolicyTestSignBeforeConfigure(t, domain)
}

func venafiPolicyTestSignBeforeConfigure(t *testing.T, domain string) {
	b, storage := createBackendWithStorage(t)
	rootData := map[string]interface{}{
		"common_name": domain,
		"ttl":         "6h",
	}
	resp, _ := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   storage,
		Data:      rootData,
	})
	if resp == nil {
		t.Fatalf("Error should be generated in response")
	}
	if resp.Error() == nil {
		t.Fatalf("Should fail to generate root before configuring policy")
	}
}

func TestVenafiPolicyCloudWriteAndReadPolicy(t *testing.T) {
	_, policyData := makeVenafiCloudConfig()
	venafiPolicyWriteAndReadTest(t, policyData)
}

func TestVenafiPolicyTPPWriteAndReadPolicy(t *testing.T) {
	_, policyData := makeVenafiTPPConfig()
	venafiPolicyWriteAndReadTest(t, policyData)
}

func venafiPolicyWriteAndReadTest(t *testing.T, policyData map[string]interface{}) {
	// create the backend
	b, storage := createBackendWithStorage(t)

	resp := writePolicy(b, storage, policyData, t, defaultVenafiPolicyName)

	log.Println("After write policy should be on output")
	for key, value := range resp.Data {
		log.Println(key, ":", value)
	}

	log.Println("Read saved policy configuration")
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      venafiPolicyPath + defaultVenafiPolicyName,
		Storage:   storage,
	})

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to read venafi policy from "+venafiPolicyPath+defaultVenafiPolicyName+"/policy, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	for key, value := range resp.Data {
		log.Println(key, ":", value)
	}

	log.Println("Check expected policy config properties")
	if resp.Data["zone"].(string) != policyData["zone"] {
		t.Fatalf("%s != %s", resp.Data["zone"].(string), policyData["zone"])
	}

	log.Println("Read saved Venafi policy content")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      venafiPolicyPath + defaultVenafiPolicyName + "/policy",
		Storage:   storage,
	})

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to read venafi policy from "+venafiPolicyPath+defaultVenafiPolicyName+"policy, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	for key, value := range resp.Data {
		log.Println(key, ":", value)
	}

	log.Println("Read Venafi policy content from wrong path")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      venafiPolicyPath + "wrong-path/policy",
		Storage:   storage,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp.Data["error"] != "policy data is nil. Looks like it doesn't exists." {
		t.Fatalf("should faile to read venafi policy from "+venafiPolicyPath+"wrong-path/policy, %#v", resp)
	}

	for key, value := range resp.Data {
		log.Println(key, ":", value)
	}

}

func Test_pathVenafiRolePolicy(t *testing.T) {

	policy := copyMap(policyCloudData)
	testRoleName := "test-role"
	policy[policyFieldDefaultsRoles] = testRoleName
	policy[policyFieldEnforcementRoles] = testRoleName
	policy[policyFieldImportRoles] = testRoleName

	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	writePolicy(b, storage, policy, t, defaultVenafiPolicyName)

	//read policy map
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      venafiRolePolicyPath + testRoleName,
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to read policy map, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		have string
		want string
	}{
		{resp.Data["defaults_policy"].(string), "default"},
		{resp.Data["enforcement_policy"].(string), "default"},
		{resp.Data["import_policy"].(string), "default"},
	}
	for _, tt := range tests {
		t.Run("check policy for role", func(t *testing.T) {
			if tt.have != tt.want {
				t.Fatalf("%s doesn't match %s", tt.have, tt.want)
			}
		})
	}

}

func Test_pathShowVenafiPolicyMap(t *testing.T) {

	policy := copyMap(policyCloudData)
	testRoleName := "test-import"

	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	writePolicy(b, storage, policy, t, defaultVenafiPolicyName)

	// create a role entry
	roleData := map[string]interface{}{
		"allowed_domains":  "test.com",
		"allow_subdomains": "true",
		"max_ttl":          "4h",
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

	//create second role
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + testRoleName + "-1",
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	policy[policyFieldDefaultsRoles] = testRoleName + "-1," + testRoleName
	writePolicy(b, storage, policy, t, defaultVenafiPolicyName+"-1")

	//create third role and write policy
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + testRoleName + "-2",
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	policy[policyFieldDefaultsRoles] = ""
	policy[policyFieldEnforcementRoles] = testRoleName + "-2"
	policy[policyFieldImportRoles] = testRoleName
	writePolicy(b, storage, policy, t, defaultVenafiPolicyName+"-2")

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      venafiRolePolicyMapPath,
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to read policy map, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	if resp.Data["policy_map_json"] == "" {
		t.Fatalf("There should be data in resp: %s", resp.Data["policy_map_json"])
	}

	var policyMap policyRoleMap
	policyMap.Roles = make(map[string]policyTypes)

	err = json.Unmarshal(resp.Data["policy_map_json"].([]byte), &policyMap)
	if err != nil {
		t.Fatalf("Can not parse policy json data: %s", err)
	}

	var want, have string

	want = defaultVenafiPolicyName + "-1"
	have = policyMap.Roles[testRoleName].DefaultsPolicy
	if want != have {
		t.Fatalf("Policy should be %s but we have %s", want, have)
	}
	want = defaultVenafiPolicyName + "-1"
	have = policyMap.Roles[testRoleName+"-1"].DefaultsPolicy
	if want != have {
		t.Fatalf("Policy should be %s but we have %s", want, have)
	}
	want = defaultVenafiPolicyName + "-2"
	have = policyMap.Roles[testRoleName+"-2"].EnforcementPolicy
	if want != have {
		t.Fatalf("Policy should be %s but we have %s", want, have)
	}

	want = defaultVenafiPolicyName + "-2"
	have = policyMap.Roles[testRoleName].ImportPolicy
	if want != have {
		t.Fatalf("Policy should be %s but we have %s", want, have)
	}
	b.taskStorage.stop = true
}

//TODO: add test with empty organization
//TODO: add test for CA with emoty organization
//TODO: add test for CA with SANs
func venafiPolicyTests(t *testing.T, policyData map[string]interface{}, domain string) {
	// create the backend
	rand := randSeq(9)
	b, storage := createBackendWithStorage(t)
	writePolicy(b, storage, policyData, t, defaultVenafiPolicyName)

	t.Log("Setting up role")
	roleData := map[string]interface{}{
		"organization":       "Venafi Inc.",
		"ou":                 "Integration",
		"locality":           "Salt Lake",
		"province":           "Utah",
		"country":            "US",
		"allowed_domains":    domain,
		"allow_subdomains":   "true",
		"max_ttl":            "4h",
		"allow_bare_domains": true,
		"generate_lease":     true,
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
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

	rootData := map[string]interface{}{
		"common_name":  "ca.some.domain",
		"organization": "Venafi Inc.",
		"ou":           "Integration",
		"locality":     "Salt Lake",
		"province":     "Utah",
		"country":      "US",
		"ttl":          "6h",
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   storage,
		Data:      rootData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to generate internal root CA, %#v", resp)
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

	log.Println("issue proper cert with empty SAN")
	singleCN := rand + "-policy." + domain
	certData := map[string]interface{}{
		"common_name": singleCN,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/test-venafi-policy",
		Storage:   storage,
		Data:      certData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue a cert, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	log.Println("issue proper cert with SANs")
	singleCN = rand + "-policy." + domain
	certData = map[string]interface{}{
		"common_name": singleCN,
		"alt_names":   "foo." + domain + ",bar." + domain,
		"ip_sans":     "1.2.3.4",
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/test-venafi-policy",
		Storage:   storage,
		Data:      certData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue a cert, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	log.Println("issue cert with wrong CN")
	singleCN = rand + "-import." + "wrong.wrong"
	certData = map[string]interface{}{
		"common_name": singleCN,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/test-venafi-policy",
		Storage:   storage,
		Data:      certData,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err_msg, prsnt := resp.Data["error"]; prsnt {
		if !strings.Contains(err_msg.(string), "doesn't match regexps") {
			t.Fatalf(msg_denied_by_policy, resp)
		}
	} else {
		t.Fatalf(msg_denied_by_policy, resp)
	}

	wrong_params := map[string]string{
		"organization": "Wrong Organization",
		"ou":           "Wrong Organization Unit",
		"locality":     "Wrong Locality",
		"province":     "Wrong State",
		"country":      "Wrong Country",
	}

	for key, value := range wrong_params {
		log.Println("Setting up role with wrong", key)
		wrongRoleData := map[string]interface{}{
			"allowed_domains":    domain,
			"allow_subdomains":   "true",
			"max_ttl":            "4h",
			"allow_bare_domains": true,
			"generate_lease":     true,
			key:                  value,
		}

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/test-venafi-policy",
			Storage:   storage,
			Data:      wrongRoleData,
		})

		if resp != nil && resp.IsError() {
			t.Fatalf("failed to create a role, %#v", resp)
		}
		if err != nil {
			t.Fatal(err)
		}

		log.Println("issue cert with wrong", key)
		singleCN = rand + "-policy." + domain
		certData = map[string]interface{}{
			"common_name": singleCN,
		}

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "issue/test-venafi-policy",
			Storage:   storage,
			Data:      certData,
		})
		if err != nil {
			t.Fatal(err)
		}

		if err_msg, prsnt := resp.Data["error"]; prsnt {
			if !strings.Contains(err_msg.(string), "doesn't match regexps") {
				t.Fatalf(msg_denied_by_policy, resp)
			}
		} else {
			t.Fatalf(msg_denied_by_policy, resp)
		}
	}

	log.Println("Write normal parameters back")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-venafi-policy",
		Storage:   storage,
		Data:      roleData,
	})

	log.Println("Testing wrong CSR signing")
	certData = map[string]interface{}{
		"csr": wrong_csr,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sign/test-venafi-policy",
		Storage:   storage,
		Data:      certData,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err_msg, prsnt := resp.Data["error"]; prsnt {
		if !strings.Contains(err_msg.(string), "doesn't match regexps") {
			t.Fatalf(msg_denied_by_policy, resp)
		}
	} else {
		t.Fatalf(msg_denied_by_policy, resp)
	}

	log.Println("Testing proper CSR signing")
	certData = map[string]interface{}{
		"csr": allowed_csr,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sign/test-venafi-policy",
		Storage:   storage,
		Data:      certData,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue a cert, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data["certificate"] == nil {
		t.Fatalf("certificate field shouldn't be nil, %#v", resp)
	}

	log.Println("Testing proper CSR without alt names")
	certData = map[string]interface{}{
		"csr": allowed_empty_csr,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sign/test-venafi-policy",
		Storage:   storage,
		Data:      certData,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue a cert, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data["certificate"] == nil {
		t.Fatalf("certificate field shouldn't be nil, %#v", resp)
	}

	//TODO: add test with wrong key types

	log.Println("Writing second Venafi policy configuration")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      venafiPolicyPath + "second",
		Storage:   storage,
		Data:      policyData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to configure venafi policy, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatalf("after write policy should be on output, but response is nil: %#v", resp)
	}

	log.Println("Listing Venafi policies")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      venafiPolicyPath,
		Storage:   storage,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to list policies, %#v", resp)
	}

	if err != nil {
		t.Fatal(err)
	}

	keys := resp.Data["keys"]
	log.Printf("Policy list is:\n %v", keys)

	log.Println("Deleting Venafi policy default")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      venafiPolicyPath + defaultVenafiPolicyName,
		Storage:   storage,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to delete policy, %#v", resp)
	}

	if err != nil {
		t.Fatal(err)
	}

	log.Println("Listing Venafi policies")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      venafiPolicyPath,
		Storage:   storage,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to list policies, %#v", resp)
	}

	if err != nil {
		t.Fatal(err)
	}

	keys = resp.Data["keys"]
	log.Printf("Policy list is:\n %v", keys)
	//TODO: check that keys is list of [default second]

	log.Println("Creating PKI role for policy second")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-venafi-second-policy",
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	//TODO: this action should be removed after implementing that writing policy will also update the role
	log.Println("Updating second Venafi policy configuration to match role second")
	policyData[policyFieldDefaultsRoles] = ""
	policyData[policyFieldEnforcementRoles] = "test-venafi-second-policy"
	policyData[policyFieldImportRoles] = "test-venafi-second-policy"
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      venafiPolicyPath + "second",
		Storage:   storage,
		Data:      policyData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to configure venafi policy, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatalf("after write policy should be on output, but response is nil: %#v", resp)
	}

	log.Println("Issuing certificate for policy second")
	singleCN = rand + "-import-second-policy." + domain
	certData = map[string]interface{}{
		"common_name": singleCN,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/test-venafi-second-policy",
		Storage:   storage,
		Data:      certData,
	})

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue a cert, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	log.Println("Deleting Venafi policy second")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      venafiPolicyPath + "second",
		Storage:   storage,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to delete policy, %#v", resp)
	}

	if err != nil {
		t.Fatal(err)
	}

	log.Println("Listing Venafi policies")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      venafiPolicyPath,
		Storage:   storage,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to list policies, %#v", resp)
	}

	if err != nil {
		t.Fatal(err)
	}

	keys = resp.Data["keys"]
	log.Printf("Policy list is:\n %v", keys)
	//TODO: check that keys is list of [second]

	log.Println("Trying to sign certificate with deleted policy")
	singleCN = rand + "-import-deleted-policy." + domain
	certData = map[string]interface{}{
		"common_name": singleCN,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/test-venafi-policy",
		Storage:   storage,
		Data:      certData,
	})
	if resp == nil {
		t.Fatalf("Error should be generated in response")
	}
	if resp.Error() == nil {
		t.Fatalf("Should fail to generate certificate after deleting policy")
	}

}

func Test_refreshVenafiPolicyEnforcementContent(t *testing.T) {
	b, storage := createBackendWithStorage(t)
	ctx := context.Background()

	t.Log("writing TPP configuration")

	t.Log("writing Cloud configuration")
	writePolicy(b, storage, venafiTestCloudConfigAllAllow, t, "cloud-policy")
	t.Log("writing TPP no refresh policy")
	writePolicy(b, storage, venafiTestTPPConfigNoRefresh, t, "tpp-policy-no-refresh")
	t.Log("writing bad data policy")
	writePolicy(b, storage, venafiTestConfigBadData, t, "policy-bad-data")

	type args struct {
		policyName string
		policyData map[string]interface{}
	}
	tests := []struct {
		name string
		args args
		want error
	}{
		{"refresh TPP enforcement", args{"tpp-policy", venafiTestTPPConfigAllAllow}, nil},
		{"refresh Cloud enforcement", args{"cloud-policy", venafiTestCloudConfigAllAllow}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writePolicy(b, storage, tt.args.policyData, t, tt.args.policyName)
			if got := b.refreshVenafiPolicyEnforcementContent(ctx, storage, tt.args.policyName); got != tt.want {
				t.Errorf("error: %v, want %v", got, tt.want)
			}
		})
	}

}

func Test_syncPolicyEnforcementAndRoleDefaults(t *testing.T) {
	// create the backend
	ctx := context.Background()
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b := Backend(config)

	type args struct {
		policyName    string
		policyData    map[string]interface{}
		roleName      string
		wantRoleEntry roleEntry
	}
	tests := []struct {
		name string
		args args
	}{
		//{"sync TPP", args{"tpp-policy", venafiTestTPPConfigAllAllow, "tpp-role", wantTPPRoleEntry}},
		{"sync Cloud", args{"cloud-policy", venafiTestCloudConfigRestricted, "cloud-role", wantCloudRoleEntry}},
		{"sync Cloud no refresh", args{"cloud-policy", venafiTestCloudConfigNoRefresh, "cloud-role-no-refresh", wantEmptyRoleEntry}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyData := copyMap(tt.args.policyData)
			policyData[policyFieldDefaultsRoles] = tt.args.roleName
			policyData[policyFieldEnforcementRoles] = tt.args.roleName
			writePolicy(b, storage, policyData, t, tt.args.roleName)
			//Cleanup role before doing refresh
			b.setupRole(t, tt.args.roleName, storage, emptyRoleData)
			err := b.syncPolicyEnforcementAndRoleDefaults(config)
			if err != nil {
				t.Error(err)
			}
			t.Log("Checking data for the first role")
			roleEntryData, err := b.getPKIRoleEntry(ctx, storage, tt.args.roleName)

			if err != nil {
				t.Fatal(err)
			}

			if roleEntryData == nil {
				t.Fatal("role entry should not be nil")
			}
			checkRoleEntry(t, *roleEntryData, tt.args.wantRoleEntry)
		})
	}

}

func Test_updateRolesPolicyAttributes(t *testing.T) {
	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	req := &logical.Request{

		Storage: storage,
	}

	enforcementRoles := []string{"role1", "role2", "role3"}
	defaultsRoles := []string{"role1", "role2", "role3", "role4", "role6"}
	importRoles := []string{"role4", "role5"}
	var rolesTypesMap map[string][]string
	rolesTypesMap = make(map[string][]string)

	rolesTypesMap[policyFieldEnforcementRoles] = enforcementRoles
	rolesTypesMap[policyFieldDefaultsRoles] = defaultsRoles
	rolesTypesMap[policyFieldImportRoles] = importRoles

	var policyMap policyRoleMap
	policyMap.Roles = make(map[string]policyTypes)
	r := policyTypes{}
	r.EnforcementPolicy = "policyForRole6"
	policyMap.Roles["role6"] = r
	r = policyTypes{}
	//This should be rewrited
	r.DefaultsPolicy = "rewriteMePlease"
	policyMap.Roles["role1"] = r

	newPolicy := "newPolicy"
	policy := copyMap(policyTPPData)
	writePolicy(b, storage, policy, t, newPolicy)

	err = b.updateRolesPolicyAttributes(ctx, req, rolesTypesMap, newPolicy, true, policyMap)
	if err != nil {
		t.Fatal(err)
	}

	policyMapNew, err := getPolicyRoleMap(ctx, storage)
	if err != nil {
		return
	}
	fmt.Println(policyMapNew)

	tests := []struct {
		have string
		want string
	}{
		{policyMapNew.Roles["role1"].EnforcementPolicy, newPolicy},
		{policyMapNew.Roles["role1"].EnforcementPolicy, newPolicy},
		{policyMapNew.Roles["role2"].EnforcementPolicy, newPolicy},
		{policyMapNew.Roles["role3"].EnforcementPolicy, newPolicy},
		{policyMapNew.Roles["role1"].ImportPolicy, ""},
		{policyMapNew.Roles["role2"].ImportPolicy, ""},
		{policyMapNew.Roles["role3"].ImportPolicy, ""},
		{policyMapNew.Roles["role1"].DefaultsPolicy, newPolicy},
		{policyMapNew.Roles["role2"].DefaultsPolicy, newPolicy},
		{policyMapNew.Roles["role3"].DefaultsPolicy, newPolicy},
		{policyMapNew.Roles["role4"].DefaultsPolicy, newPolicy},
		{policyMapNew.Roles["role6"].DefaultsPolicy, newPolicy},
		{policyMapNew.Roles["role4"].ImportPolicy, newPolicy},
		{policyMapNew.Roles["role5"].ImportPolicy, newPolicy},
		{policyMapNew.Roles["role6"].EnforcementPolicy, "policyForRole6"},
	}
	for _, tt := range tests {
		t.Run("check policy", func(t *testing.T) {
			if tt.have != tt.want {
				t.Fatalf("%s doesn't match %s", tt.have, tt.want)
			}
		})
	}

	for _, roleName := range defaultsRoles {
		t.Log("Checking that roles was created by policy")
		roleReq := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "roles/" + roleName,
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), roleReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("bad: err: %v resp: %#v", err, resp)
		}

		t.Log("Checking that role values are not nil")
		testsNotNil := []struct {
			name string
			have interface{}
		}{
			{"organization", resp.Data["organization"]},
			{"ou", resp.Data["ou"]},
			{"locality", resp.Data["locality"]},
			{"province", resp.Data["province"]},
			{"country", resp.Data["country"]},
		}

		for _, tt := range testsNotNil {
			if reflect.ValueOf(tt.have).IsNil() {
				t.Fatalf("%s is nil", tt.name)
			}
		}

		t.Log("Checking role values")
		testsRole := []struct {
			have []string
			want []string
		}{
			{resp.Data["organization"].([]string), wantTPPRoleEntry.Organization},
			{resp.Data["ou"].([]string), wantTPPRoleEntry.OU},
			{resp.Data["locality"].([]string), wantTPPRoleEntry.Locality},
			{resp.Data["province"].([]string), wantTPPRoleEntry.Province},
			{resp.Data["country"].([]string), wantTPPRoleEntry.Country},
		}
		for _, tt := range testsRole {
			t.Run("check role", func(t *testing.T) {
				if !strutil.StrListSubset(tt.have, tt.want) {
					t.Fatalf("%s doesn't match %s", tt.have, tt.want)
				}
			})
		}
	}

}

func Test_updateRolesPolicyAttributes_DoNotCreateRole(t *testing.T) {
	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	req := &logical.Request{
		Storage: storage,
	}

	enforcementRoles := []string{"role1", "role2", "role3"}
	defaultsRoles := []string{"role1", "role2", "role3", "role4", "role6"}
	importRoles := []string{"role4", "role5"}
	var rolesTypesMap map[string][]string
	rolesTypesMap = make(map[string][]string)

	rolesTypesMap[policyFieldEnforcementRoles] = enforcementRoles
	rolesTypesMap[policyFieldDefaultsRoles] = defaultsRoles
	rolesTypesMap[policyFieldImportRoles] = importRoles

	var policyMap policyRoleMap
	policyMap.Roles = make(map[string]policyTypes)
	r := policyTypes{}
	r.EnforcementPolicy = "default"
	policyMap.Roles["role6"] = r
	r = policyTypes{}
	r.DefaultsPolicy = "default"
	policyMap.Roles["role1"] = r

	err = b.updateRolesPolicyAttributes(ctx, req, rolesTypesMap, "default", false, policyMap)
	if err == nil {
		t.Fatal("Update attribute should fail if role does not exists")
	}

	expectedErr := "role role1 does not exists. can not add it to the attributes of policy default"
	if err.Error() != expectedErr {
		t.Fatalf("Expected error is %s, but we have: %s", expectedErr, err)
	}
	t.Logf("Err: %s", err)
}

func Test_getPolicyRoleMap(t *testing.T) {

	storage := &logical.InmemStorage{}
	ctx := context.Background()

	var policyMap policyRoleMap
	policyMap.Roles = make(map[string]policyTypes)
	r := policyTypes{}
	r.EnforcementPolicy = "policy1"
	policyMap.Roles["role1"] = r
	r = policyTypes{}
	r.DefaultsPolicy = "policy2"
	policyMap.Roles["role2"] = r

	jsonEntry, err := logical.StorageEntryJSON(venafiRolePolicyMapStorage, policyMap)

	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, jsonEntry); err != nil {
		t.Fatal(err)
	}

	policyMapGot, err := getPolicyRoleMap(ctx, storage)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		have string
		want string
	}{
		{"Check policy1", policyMapGot.Roles["role1"].EnforcementPolicy, "policy1"},
		{"Check policy2", policyMapGot.Roles["role2"].DefaultsPolicy, "policy2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.have != tt.want {
				t.Fatalf("%s doesn't match %s", tt.have, tt.want)
			}
		})
	}

}

func TestAssociateOrphanRolesWithDefaultPolicy(t *testing.T) {
	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	testRoleName := "test-venafi-role"
	testRoleName2 := "test-venafi-role2"
	testRoleName3 := "test-venafi-role3"
	testRoleName4 := "test-venafi-role4"
	testRoleName5 := "test-venafi-role5"
	config.StorageView = storage

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Setting up first role")
	b.setupRole(t, testRoleName, storage, roleData)

	t.Log("Setting up second role")
	b.setupRole(t, testRoleName2, storage, roleData)

	t.Log("Setting up third role")
	b.setupRole(t, testRoleName3, storage, roleData)

	t.Log("Setting up fourth role")
	b.setupRole(t, testRoleName4, storage, roleData)

	t.Log("Setting up fifth role")
	b.setupRole(t, testRoleName5, storage, roleData)

	t.Log("Setting up non default policy")
	policy := copyMap(policyTPPData)
	policy[policyFieldDefaultsRoles] = fmt.Sprintf("%s,%s", testRoleName, testRoleName2)
	policy[policyFieldEnforcementRoles] = fmt.Sprintf("%s,%s", testRoleName, testRoleName2)
	policy[policyFieldImportRoles] = fmt.Sprintf("%s,%s,%s", testRoleName, testRoleName2, testRoleName5)
	writePolicy(b, storage, policy, t, "non-default")

	t.Log("Setting up default policy. Other roles should be added to it")
	policy2 := copyMap(policyTPPData)
	writePolicy(b, storage, policy2, t, "default")

	ctx := context.Background()
	policyMap, err := getPolicyRoleMap(ctx, storage)
	if err != nil {
		return
	}
	t.Log("Checking that roles 3 and 4 is in default policy")
	for _, name := range []string{testRoleName3, testRoleName4} {
		if policyMap.Roles[name].DefaultsPolicy != "default" {
			t.Fatalf("%s role is not in default policy defaults", name)
		}
		if policyMap.Roles[name].EnforcementPolicy != "default" {
			t.Fatalf("%s role is not in default policy enforcement", name)
		}
		if policyMap.Roles[name].ImportPolicy != "" {
			t.Fatalf("%s role should not be in policy import", name)
		}
	}
}

func Test_fillPolicyMapWithRoles(t *testing.T) {

	type args struct {
		policyMap  policyRoleMap
		roleName   string
		policyName string
		roleType   string
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fillPolicyMapWithRoles(tt.args.policyMap, tt.args.roleName, tt.args.policyName, tt.args.roleType)
		})
	}
}
