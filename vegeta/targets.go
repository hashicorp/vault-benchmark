package vegeta

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type targetFraction struct {
	name       string
	method     string
	pathPrefix string
	percent    int // e.g. 30 is 30%
	target     func(*api.Client) vegeta.Target
}

// TargetMulti allows building a vegeta targetter that chooses between various
// operations randomly following a specified distribution.
type TargetMulti struct {
	fractions []targetFraction
}

func (tm TargetMulti) validate() error {
	total := 0
	for _, fraction := range tm.fractions {
		total += fraction.percent
	}
	if total != 100 {
		return fmt.Errorf("total comes to %d, should be 100", total)
	}
	return nil
}

func (tm TargetMulti) choose(i int) targetFraction {
	if i > 99 || i < 0 {
		panic("i must be between 0 and 99")
	}

	total := 0
	for _, fraction := range tm.fractions {
		total += fraction.percent
		if i < total {
			return fraction
		}
	}

	panic("unreachable")
}

func (tm TargetMulti) Targeter(client *api.Client) (vegeta.Targeter, error) {
	if err := tm.validate(); err != nil {
		return nil, err
	}
	return func(tgt *vegeta.Target) error {
		if tgt == nil {
			return vegeta.ErrNilTarget
		}
		rnd := int(rand.Int31n(100))
		f := tm.choose(rnd)
		*tgt = f.target(client)
		return nil
	}, nil
}

func (tm TargetMulti) DebugInfo(client *api.Client) {
	for index, fraction := range tm.fractions {
		fmt.Printf("Target %d: %v\n", index, fraction.name)
		fmt.Printf("\tMethod: %v\n", fraction.method)
		fmt.Printf("\tPath Prefix: %v\n", string(fraction.pathPrefix))
		target := fraction.target(client)
		req, err := target.Request()
		if err != nil {
			panic(fmt.Sprintf("Got err building target: %v", err))
		}
		fmt.Printf("\tRequest: %v\n", req)
		fmt.Printf("\tRequest Body: %v\n", string(target.Body))
		resp, err := client.CloneConfig().HttpClient.Do(req)
		if err != nil {
			panic(fmt.Sprintf("Got err executing target request: %v", err))
		}
		rawBody, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(fmt.Sprintf("Got err reading response body: %v", err))
		}
		fmt.Printf("\tResponse: %v\n", resp)
		fmt.Printf("\tResponse Body: %v\n", string(rawBody))
		if resp.StatusCode >= 400 {
			panic(fmt.Sprintf("Got error response from server on testing request; exiting"))
		}
		fmt.Println()
	}
}

type kvv1test struct {
	pathPrefix string
	header     http.Header
	numKVs     int
	kvSize     int
}

func (k *kvv1test) read(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(k.numKVs)))
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + k.pathPrefix + "/secret-" + strconv.Itoa(secnum),
		Header: k.header,
	}
}

func (k *kvv1test) write(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(k.numKVs)))
	value := strings.Repeat("a", k.kvSize)
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + k.pathPrefix + "/secret-" + strconv.Itoa(secnum),
		Body:   []byte(`{"data": {"foo": "` + value + `"}}`),
		Header: k.header,
	}
}

type kvv2test struct {
	pathPrefix string
	header     http.Header
	numKVs     int
	kvSize     int
}

func (k *kvv2test) read(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(k.numKVs)))
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + k.pathPrefix + "/data/secret-" + strconv.Itoa(secnum),
		Header: k.header,
	}
}

func (k *kvv2test) write(client *api.Client) vegeta.Target {
	secnum := int(1 + rand.Int31n(int32(k.numKVs)))
	value := strings.Repeat("a", k.kvSize)
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + k.pathPrefix + "/data/secret-" + strconv.Itoa(secnum),
		Header: k.header,
		Body:   []byte(`{"data": {"foo": "` + value + `"}}`),
	}
}

type approletest struct {
	pathPrefix string
	role       string
	roleID     string
	header     http.Header
	secretID   string
}

func (a *approletest) login(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + a.pathPrefix + "/login",
		Header: a.header,
		Body:   []byte(fmt.Sprintf(`{"role_id": "%s", "secret_id": "%s"}`, a.roleID, a.secretID)),
	}
}

func setupApprole(client *api.Client, randomMounts bool, ttl time.Duration) (*approletest, error) {
	authPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		authPath = "approle"
	}

	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling approle: %v", err)
	}

	role := "role1"
	rolePath := filepath.Join("auth", authPath, "role", role)
	_, err = client.Logical().Write(rolePath, map[string]interface{}{
		"token_ttl":     int(ttl.Seconds()),
		"token_max_ttl": int(ttl.Seconds()),
		"secret_id_ttl": int((1000 * time.Hour).Seconds()),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating approle role %q: %v", role, err)
	}

	secretRole, err := client.Logical().Read(rolePath + "/role-id")
	if err != nil {
		return nil, fmt.Errorf("error reading approle role_id: %v", err)
	}

	secretId, err := client.Logical().Write(rolePath+"/secret-id", nil)
	if err != nil {
		return nil, fmt.Errorf("error reading approle secret_id: %v", err)
	}

	return &approletest{
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		roleID:     secretRole.Data["role_id"].(string),
		role:       role,
		secretID:   secretId.Data["secret_id"].(string),
	}, nil
}

type pkiTest struct {
	pathPrefix string
	cn         string
	header     http.Header
}

func (p *pkiTest) write(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + p.pathPrefix,
		Body:   []byte(fmt.Sprintf(`{"common_name": "%s"}`, p.cn)),
		Header: p.header,
	}
}

func setupPKI(client *api.Client, randomMounts bool, config PkiTestConfig) (*pkiTest, error) {
	pkiPathPrefix, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	if !randomMounts {
		pkiPathPrefix = "pki"
	}

	err = createRootCA(client, pkiPathPrefix, config)
	if err != nil {
		return nil, err
	}
	path, cn, err := createIntermediateCA(client, pkiPathPrefix, config)
	if err != nil {
		return nil, err
	}

	return &pkiTest{
		pathPrefix: "/v1/" + path,
		cn:         cn,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
	}, nil
}

func createRootCA(cli *api.Client, pfx string, config PkiTestConfig) error {
	rootPath := pfx + "-root"
	err := cli.Sys().Mount(rootPath, &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil {
		return err
	}

	// Avoid slow mount setup:
	// URL: PUT $VAULT_ADDR/v1/9679cb02-65a4-f625-2f27-68d51e46af46-root/root/generate/internal
	// Code: 404. Errors: * no handler for route "9679cb02-65a4-f625-2f27-68d51e46af46-root/root/generate/internal". route entry not found.
	time.Sleep(config.SetupDelay)

	_, err = cli.Logical().Write(rootPath+"/root/generate/internal", map[string]interface{}{
		"common_name": "example.com",
		"ttl":         "87600h",
		"key_type":    config.RootKeyType,
		"key_bits":    config.RootKeyBits,
	})
	if err != nil {
		return err
	}

	_, err = cli.Logical().Write(rootPath+"/config/urls", map[string]interface{}{
		"issuing_certificates":   fmt.Sprintf("%s/v1/%s/ca", cli.Address(), rootPath),
		"crl_distribution_point": fmt.Sprintf("%s/v1/%s/crl", cli.Address(), rootPath),
	})
	return err
}

func createIntermediateCA(cli *api.Client, pfx string, config PkiTestConfig) (string, string, error) {
	rootPath, intPath := pfx+"-root", pfx+"-int"

	err := cli.Sys().Mount(intPath, &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil {
		return "", "", err
	}

	// Avoid slow mount setup:
	// URL: PUT $VAULT_ADDR/v1/9679cb02-65a4-f625-2f27-68d51e46af46-root/root/generate/internal
	// Code: 404. Errors: * no handler for route "9679cb02-65a4-f625-2f27-68d51e46af46-root/root/generate/internal". route entry not found.
	time.Sleep(config.SetupDelay)

	resp, err := cli.Logical().Write(intPath+"/intermediate/generate/internal", map[string]interface{}{
		"common_name": "example.com Intermediate Authority",
		"ttl":         "87600h",
		"key_type":    config.IntKeyType,
		"key_bits":    config.IntKeyBits,
	})
	if err != nil {
		return "", "", err
	}

	resp, err = cli.Logical().Write(rootPath+"/root/sign-intermediate", map[string]interface{}{
		"csr":    resp.Data["csr"].(string),
		"format": "pem_bundle",
		"ttl":    "43800h",
	})
	if err != nil {
		return "", "", err
	}

	_, err = cli.Logical().Write(intPath+"/intermediate/set-signed", map[string]interface{}{
		"certificate": strings.Join([]string{resp.Data["certificate"].(string), resp.Data["issuing_ca"].(string)}, "\n"),
	})
	if err != nil {
		return "", "", err
	}

	resp, err = cli.Logical().Write(intPath+"/roles/consul-server", map[string]interface{}{
		"allowed_domains":  "server.dc1.consul",
		"allow_subdomains": "true",
		"allow_localhost":  "true",
		"allow_any_name":   "true",
		"allow_ip_sans":    "true",
		"max_ttl":          "720h",
		"generate_lease":   fmt.Sprintf("%t", config.LeafLease),
		"no_store":         fmt.Sprintf("%t", !config.LeafStore),
		"key_type":         config.LeafKeyType,
		"key_bits":         config.LeafKeyBits,
	})
	if err != nil {
		return "", "", err
	}

	return intPath + "/issue/consul-server", "server.dc1.consul", nil
}

type sshTest struct {
	pathPrefix string
	keyType    string
	keyBits    int
	header     http.Header
}

func (s *sshTest) write(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + s.pathPrefix,
		Body:   []byte(fmt.Sprintf(`{"key_type": "%s", "key_bits": "%d"}`, s.keyType, s.keyBits)),
		Header: s.header,
	}
}

func setupSSH(client *api.Client, randomMounts bool, config SshCaTestConfig) (*sshTest, error) {
	sshPathPrefix, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	sshPathPrefix += "-ssh"
	if !randomMounts {
		sshPathPrefix = "ssh"
	}

	err = client.Sys().Mount(sshPathPrefix, &api.MountInput{
		Type: "ssh",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil {
		return nil, err
	}

	_, err = client.Logical().Write(sshPathPrefix+"/config/ca", map[string]interface{}{
		"common_name": "example.com",
		"ttl":         "87600h",
		"key_type":    config.CAKeyType,
		"key_bits":    config.CAKeyBits,
	})
	if err != nil {
		return nil, err
	}

	_, err = client.Logical().Write(sshPathPrefix+"/roles/consul-server", map[string]interface{}{
		"key_type":                "ca",
		"allow_user_certificates": "true",
	})
	if err != nil {
		return nil, err
	}

	return &sshTest{
		pathPrefix: "/v1/" + sshPathPrefix + "/issue/consul-server",
		keyType:    config.LeafKeyType,
		keyBits:    config.LeafKeyBits,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
	}, nil
}

type transitTest struct {
	pathPrefix string
	body       []byte
	header     http.Header
}

func (t *transitTest) write(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + t.pathPrefix,
		Body:   t.body,
		Header: t.header,
	}
}

func setupTransit(client *api.Client, randomMounts bool, operation string, config transitTestConfig) (*transitTest, error) {
	pathPrefix, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	pathPrefix += "-transit-" + operation
	if !randomMounts {
		pathPrefix = "transit-" + operation
	}

	err = client.Sys().Mount(pathPrefix, &api.MountInput{
		Type: "transit",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil {
		return nil, err
	}

	// Generate keys if it isn't the subject of our benchmark.
	if operation != "generate" {
		_, err = client.Logical().Write(pathPrefix+"/keys/testing", map[string]interface{}{
			"derived":               config.Derived,
			"convergent_encryption": config.Convergent,
			"type":                  config.KeyType,
		})
	}

	ret := &transitTest{
		pathPrefix: "/v1/" + pathPrefix,
		body:       []byte(""),
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
	}

	// Generate our payload and context
	rawPayload, err := uuid.GenerateRandomBytes(config.PayloadLen)
	if err != nil {
		return nil, err
	}
	base64Payload := base64.StdEncoding.EncodeToString(rawPayload)

	rawContext, err := uuid.GenerateRandomBytes(config.ContextLen)
	if err != nil {
		return nil, err
	}
	base64Context := base64.StdEncoding.EncodeToString(rawContext)

	// Now dispatch the operation.
	switch operation {
	case "sign":
		ret.pathPrefix += "/sign/testing"
		ret.body = []byte(fmt.Sprintf(`{"hash_algorithm":"%s","input":"%s","signature_algorithm":"%s","marshaling_algorithm":"%s"}`, config.Hash, base64Payload, config.SignatureAlgorithm, config.MarshalingAlgorithm))
	case "verify":
		resp, err := client.Logical().Write(pathPrefix+"/sign/testing", map[string]interface{}{
			"hash_algorithm":       config.Hash,
			"input":                base64Payload,
			"signature_algorithm":  config.SignatureAlgorithm,
			"marshaling_algorithm": config.MarshalingAlgorithm,
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || len(resp.Data["signature"].(string)) == 0 {
			return nil, fmt.Errorf("unable to sign data: no response or invalid signature: %v", resp)
		}

		ret.pathPrefix += "/verify/testing"
		ret.body = []byte(fmt.Sprintf(`{"hash_algorithm":"%s","input":"%s","signature":"%s","signature_algorithm":"%s","marshaling_algorithm":"%s"}`, config.Hash, base64Payload, resp.Data["signature"], config.SignatureAlgorithm, config.MarshalingAlgorithm))
	case "encrypt":
		ret.pathPrefix += "/encrypt/testing"

		contextStr := ""
		if config.Derived {
			contextStr = fmt.Sprintf(`,"context":"%s"`, base64Context)
		}

		ret.body = []byte(fmt.Sprintf(`{"plaintext":"%s"%s}`, base64Payload, contextStr))
	case "decrypt":
		data := map[string]interface{}{
			"plaintext": base64Payload,
		}
		if config.Derived {
			data["context"] = base64Context
		}

		resp, err := client.Logical().Write(pathPrefix+"/encrypt/testing", data)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Data["ciphertext"] == nil || len(resp.Data["ciphertext"].(string)) == 0 {
			return nil, fmt.Errorf("unable to encrypt data: no response or invalid ciphertext: %v", resp)
		}

		contextStr := ""
		if config.Derived {
			contextStr = fmt.Sprintf(`,"context":"%s"`, base64Context)
		}

		ret.pathPrefix += "/decrypt/testing"
		ret.body = []byte(fmt.Sprintf(`{"ciphertext":"%s"%s}`, resp.Data["ciphertext"], contextStr))
	default:
		return nil, fmt.Errorf("unknown or unsupported transit operation: %v", operation)
	}

	return ret, nil
}

func setupKvv1(client *api.Client, randomMounts bool, numKVs int, kvSize int) (*kvv1test, error) {
	kvv1Path, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		kvv1Path = "kvv1"
	}

	err = client.Sys().Mount(kvv1Path, &api.MountInput{
		Type: "kv",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting kvv1: %v", err)
	}

	secval := map[string]interface{}{
		"data": map[string]interface{}{
			"foo": 1,
		},
	}
	for i := 1; i <= numKVs; i++ {
		_, err = client.Logical().Write(kvv1Path+"/secret-"+strconv.Itoa(i), secval)
		if err != nil {
			return nil, fmt.Errorf("error writing kvv1: %v", err)
		}
	}

	return &kvv1test{
		pathPrefix: "/v1/" + kvv1Path,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		numKVs:     numKVs,
		kvSize:     kvSize,
	}, nil
}

func setupKvv2(client *api.Client, randomMounts bool, numKVs int, kvSize int) (*kvv2test, error) {
	kvv2Path, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		kvv2Path = "kvv2"
	}

	err = client.Sys().Mount(kvv2Path, &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting kvv2: %v", err)
	}

	secval := map[string]interface{}{
		"data": map[string]interface{}{
			"foo": 1,
		},
	}

	// Avoid error of the form:
	// * Upgrading from non-versioned to versioned data. This backend will be unavailable for a brief period and will resume service shortly.
	time.Sleep(2 * time.Second)

	for i := 1; i <= numKVs; i++ {
		_, err = client.Logical().Write(kvv2Path+"/data/secret-"+strconv.Itoa(i), secval)
		if err != nil {
			return nil, fmt.Errorf("error writing kv: %v", err)
		}
	}

	return &kvv2test{
		pathPrefix: "/v1/" + kvv2Path,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		numKVs:     numKVs,
		kvSize:     kvSize,
	}, nil
}

type PkiTestConfig struct {
	SetupDelay  time.Duration
	RootKeyType string `json:"root_key_type"`
	RootKeyBits int    `json:"root_key_bits"`
	IntKeyType  string `json:"int_key_type"`
	IntKeyBits  int    `json:"int_key_bits"`
	LeafKeyType string `json:"leaf_key_type"`
	LeafKeyBits int    `json:"leaf_key_bits"`
	LeafStore   bool   `json:"leaf_store"`
	LeafLease   bool   `json:"leaf_lease"`
}

func (p *PkiTestConfig) FromJSON(path string) error {
	// Set defaults
	p.RootKeyType = "rsa"
	p.RootKeyBits = 2048
	p.IntKeyType = "rsa"
	p.IntKeyBits = 2048
	p.LeafKeyType = "rsa"
	p.LeafKeyBits = 2048
	p.LeafStore = false
	p.LeafLease = false

	if path == "" {
		return nil
	}

	// Then load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(p); err != nil {
		return err
	}

	return nil
}

type SshCaTestConfig struct {
	SetupDelay  time.Duration
	CAKeyType   string `json:"ca_key_type"`
	CAKeyBits   int    `json:"ca_key_bits"`
	LeafKeyType string `json:"leaf_key_type"`
	LeafKeyBits int    `json:"leaf_key_bits"`
}

func (s *SshCaTestConfig) FromJSON(path string) error {
	// Set defaults
	s.CAKeyType = "rsa"
	s.CAKeyBits = 2048
	s.LeafKeyType = "rsa"
	s.LeafKeyBits = 2048

	if path == "" {
		return nil
	}

	// Then load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(s); err != nil {
		return err
	}

	return nil
}

type transitTestConfig struct {
	SetupDelay          time.Duration
	Derived             bool   `json:"derived"`
	Convergent          bool   `json:"convergent"`
	KeyType             string `json:"key_type"`
	PayloadLen          int    `json:"payload_len"`
	ContextLen          int    `json:"context_len"`
	Hash                string `json:"hash_algorithm"`
	SignatureAlgorithm  string `json:"signature_algorithm"`
	MarshalingAlgorithm string `json:"marshaling_algorithm"`
}

func (t *transitTestConfig) FromJSON(path string) error {
	// Set defaults
	t.Derived = false
	t.Convergent = false
	t.KeyType = "rsa-2048"
	t.PayloadLen = 2048
	t.ContextLen = 32
	t.Hash = "sha2-256"
	t.SignatureAlgorithm = "pss"
	t.MarshalingAlgorithm = "asn1"

	if path == "" {
		return nil
	}

	// Then load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(t); err != nil {
		return err
	}

	return nil
}

type TestSpecification struct {
	NumKVs               int
	KVSize               int
	RandomMounts         bool
	TokenTTL             time.Duration
	PctKvv1Read          int
	PctKvv1Write         int
	PctKvv2Read          int
	PctKvv2Write         int
	PctPkiIssue          int
	PkiConfig            PkiTestConfig
	PctApproleLogin      int
	PctCertLogin         int
	PctSshCaIssue        int
	SshCaConfig          SshCaTestConfig
	PctHAStatus          int
	PctSealStatus        int
	PctMetrics           int
	PctTransitSign       int
	TransitSignConfig    transitTestConfig
	PctTransitVerify     int
	TransitVerifyConfig  transitTestConfig
	PctTransitEncrypt    int
	TransitEncryptConfig transitTestConfig
	PctTransitDecrypt    int
	TransitDecryptConfig transitTestConfig
}

func BuildTargets(spec TestSpecification, client *api.Client, caPEM string) (*TargetMulti, error) {
	var tm TargetMulti

	if spec.PctKvv1Read > 0 || spec.PctKvv1Write > 0 {
		kvv1, err := setupKvv1(client, spec.RandomMounts, spec.NumKVs, spec.KVSize)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "kvv1 read",
			method:     "GET",
			pathPrefix: kvv1.pathPrefix,
			percent:    spec.PctKvv1Read,
			target:     kvv1.read,
		})
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "kvv1 write",
			method:     "POST",
			pathPrefix: kvv1.pathPrefix,
			percent:    spec.PctKvv1Write,
			target:     kvv1.write,
		})
	}
	if spec.PctKvv2Read > 0 || spec.PctKvv2Write > 0 {
		kvv2, err := setupKvv2(client, spec.RandomMounts, spec.NumKVs, spec.KVSize)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "kvv2 read",
			method:     "GET",
			pathPrefix: kvv2.pathPrefix,
			percent:    spec.PctKvv2Read,
			target:     kvv2.read,
		})
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "kvv2 write",
			method:     "POST",
			pathPrefix: kvv2.pathPrefix,
			percent:    spec.PctKvv2Write,
			target:     kvv2.write,
		})
	}

	if spec.PctApproleLogin > 0 {
		approle, err := setupApprole(client, spec.RandomMounts, spec.TokenTTL)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "approle login",
			method:     "POST",
			pathPrefix: approle.pathPrefix,
			percent:    spec.PctApproleLogin,
			target:     approle.login,
		})
	}
	if spec.PctCertLogin > 0 {
		cert, err := setupCert(client, spec.RandomMounts, spec.TokenTTL, caPEM)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "cert login",
			method:     "POST",
			pathPrefix: cert.pathPrefix,
			percent:    spec.PctCertLogin,
			target:     cert.login,
		})
	}
	if spec.PctPkiIssue > 0 {
		pki, err := setupPKI(client, spec.RandomMounts, spec.PkiConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "pki issue",
			method:     "POST",
			pathPrefix: pki.pathPrefix,
			percent:    spec.PctPkiIssue,
			target:     pki.write,
		})
	}
	if spec.PctSshCaIssue > 0 {
		ssh, err := setupSSH(client, spec.RandomMounts, spec.SshCaConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "ssh issue",
			method:     "POST",
			pathPrefix: ssh.pathPrefix,
			percent:    spec.PctSshCaIssue,
			target:     ssh.write,
		})
	}
	if spec.PctHAStatus > 0 {
		status := setupStatusTest("/v1/sys/ha-status", client)
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "ha status",
			method:     "GET",
			pathPrefix: "/v1/sys/ha-status",
			percent:    spec.PctHAStatus,
			target:     status.read,
		})
	}
	if spec.PctSealStatus > 0 {
		status := setupStatusTest("/v1/sys/seal-status", client)
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "seal status",
			method:     "GET",
			pathPrefix: "/v1/sys/seal-status",
			percent:    spec.PctSealStatus,
			target:     status.read,
		})
	}
	if spec.PctMetrics > 0 {
		status := setupStatusTest("/v1/sys/metrics", client)
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "metrics",
			method:     "GET",
			pathPrefix: "/v1/sys/metrics",
			percent:    spec.PctMetrics,
			target:     status.read,
		})
	}
	if spec.PctTransitSign > 0 {
		transit, err := setupTransit(client, spec.RandomMounts, "sign", spec.TransitSignConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "transit sign",
			method:     "POST",
			pathPrefix: transit.pathPrefix,
			percent:    spec.PctTransitSign,
			target:     transit.write,
		})
	}
	if spec.PctTransitVerify > 0 {
		transit, err := setupTransit(client, spec.RandomMounts, "verify", spec.TransitVerifyConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "transit verify",
			method:     "POST",
			pathPrefix: transit.pathPrefix,
			percent:    spec.PctTransitVerify,
			target:     transit.write,
		})
	}
	if spec.PctTransitEncrypt > 0 {
		transit, err := setupTransit(client, spec.RandomMounts, "encrypt", spec.TransitEncryptConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "transit encrypt",
			method:     "POST",
			pathPrefix: transit.pathPrefix,
			percent:    spec.PctTransitEncrypt,
			target:     transit.write,
		})
	}
	if spec.PctTransitDecrypt > 0 {
		transit, err := setupTransit(client, spec.RandomMounts, "decrypt", spec.TransitDecryptConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "transit decrypt",
			method:     "POST",
			pathPrefix: transit.pathPrefix,
			percent:    spec.PctTransitDecrypt,
			target:     transit.write,
		})
	}

	// Put the biggest fractions first as an optimization
	sort.Slice(tm.fractions, func(i, j int) bool {
		return tm.fractions[j].percent < tm.fractions[i].percent
	})

	err := tm.validate()
	if err != nil {
		return nil, err
	}
	return &tm, nil
}

type certTest struct {
	pathPrefix string
	header     http.Header
}

func setupCert(client *api.Client, randomMounts bool, ttl time.Duration, caPEM string) (*certTest, error) {
	authPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		authPath = "cert"
	}

	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "cert",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling cert: %v", err)
	}

	role := "role1"
	rolePath := filepath.Join("auth", authPath, "certs", role)
	_, err = client.Logical().Write(rolePath, map[string]interface{}{
		"token_ttl":     int(ttl.Seconds()),
		"token_max_ttl": int(ttl.Seconds()),
		"certificate":   caPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating cert role %q: %v", role, err)
	}

	return &certTest{
		pathPrefix: "/v1/auth/" + authPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
	}, nil
}

func (c *certTest) login(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + c.pathPrefix + "/login",
		Header: c.header,
	}
}

type statusTest struct {
	path   string
	header http.Header
}

func setupStatusTest(path string, client *api.Client) *statusTest {
	return &statusTest{
		path:   path,
		header: http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
	}
}

func (s *statusTest) read(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + s.path,
		Header: s.header,
	}
}
