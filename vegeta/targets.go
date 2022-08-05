package vegeta

import (
	"fmt"
	"io"
	"math/rand"
	"sort"
	"time"

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
		return fmt.Errorf("test percentage total comes to %d, should be 100", total)
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
			panic("Got error response from server on testing request; exiting")
		}
		fmt.Println()
	}
}

type TestSpecification struct {
	NumKVs                int
	KVSize                int
	RandomMounts          bool
	TokenTTL              time.Duration
	PctKvv1Read           int
	PctKvv1Write          int
	PctKvv2Read           int
	PctKvv2Write          int
	PctPkiIssue           int
	PkiConfig             PkiTestConfig
	PctApproleLogin       int
	PctCertLogin          int
	PctSshCaIssue         int
	SshCaConfig           SshCaTestConfig
	PctHAStatus           int
	PctSealStatus         int
	PctMetrics            int
	PctTransitSign        int
	TransitSignConfig     transitTestConfig
	PctTransitVerify      int
	TransitVerifyConfig   transitTestConfig
	PctTransitEncrypt     int
	TransitEncryptConfig  transitTestConfig
	PctTransitDecrypt     int
	TransitDecryptConfig  transitTestConfig
	PctCassandraRead      int
	CassandraDBConfig     CassandraDBConfig
	CassandraDBRoleConfig CassandraRoleConfig
	PctLDAPLogin          int
	LDAPAuthConfig        LDAPAuthConfig
	LDAPTestUserConfig    LDAPTestUserConfig
	PctCouchbaseRead      int
	CouchbaseConfig       CouchbaseConfig
	CouchbaseRoleConfig   CouchbaseRoleConfig
}

func BuildTargets(spec TestSpecification, client *api.Client, caPEM string, clientCAPem string) (*TargetMulti, error) {
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
		cert, err := setupCert(client, spec.RandomMounts, spec.TokenTTL, clientCAPem)
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
	if spec.PctLDAPLogin > 0 {
		ldap, err := setupLDAPAuth(client, spec.RandomMounts, &spec.LDAPAuthConfig, &spec.LDAPTestUserConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "LDAP login",
			method:     "POST",
			pathPrefix: ldap.pathPrefix,
			percent:    spec.PctLDAPLogin,
			target:     ldap.login,
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
	if spec.PctCassandraRead > 0 {
		cassandra, err := setupCassandra(client, spec.RandomMounts, &spec.CassandraDBConfig, &spec.CassandraDBRoleConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "cassandra cred retrieval",
			method:     "GET",
			pathPrefix: cassandra.pathPrefix,
			percent:    spec.PctCassandraRead,
			target:     cassandra.read,
		})
	}
	if spec.PctCouchbaseRead > 0 {
		couchbase, err := setupCouchbase(client, spec.RandomMounts, &spec.CouchbaseConfig, &spec.CouchbaseRoleConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "couchbase cred retrieval",
			method:     "GET",
			pathPrefix: couchbase.pathPrefix,
			percent:    spec.PctCouchbaseRead,
			target:     couchbase.read,
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
