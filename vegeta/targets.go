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
	cleanup    func(*api.Client) error
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

func (tm TargetMulti) Cleanup(client *api.Client) error {
	for _, fraction := range tm.fractions {
		if err := fraction.cleanup(client); err != nil {
			return err
		}
	}
	return nil
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
	Cleanup                    bool
	NumKVs                     int
	KVSize                     int
	RandomMounts               bool
	TokenTTL                   time.Duration
	PctServiceTokenCreate      int
	PctBatchTokenCreate        int
	PctKvv1Read                int
	PctKvv1Write               int
	PctKvv2Read                int
	PctKvv2Write               int
	PctPkiIssue                int
	PkiConfig                  PkiTestConfig
	PctApproleLogin            int
	PctCertLogin               int
	PctSshCaIssue              int
	SshCaConfig                SshCaTestConfig
	PctHAStatus                int
	PctSealStatus              int
	PctMetrics                 int
	PctTransitSign             int
	TransitSignConfig          transitTestConfig
	PctTransitVerify           int
	TransitVerifyConfig        transitTestConfig
	PctTransitEncrypt          int
	TransitEncryptConfig       transitTestConfig
	PctTransitDecrypt          int
	TransitDecryptConfig       transitTestConfig
	PctCassandraRead           int
	CassandraDBConfig          CassandraDBConfig
	CassandraDBRoleConfig      CassandraRoleConfig
	PctLDAPLogin               int
	LDAPAuthConfig             LDAPAuthConfig
	LDAPTestUserConfig         LDAPTestUserConfig
	PctMongoRead               int
	MongoDBConfig              MongoDBConfig
	MongoDBRoleConfig          MongoRoleConfig
	PctRabbitRead              int
	RabbitMQConfig             RabbitMQConfig
	RabbitMQRoleConfig         RabbitMQRoleConfig
	PctLDAPStaticRead          int
	PctLDAPStaticRotate        int
	PctLDAPDynamicRead         int
	LDAPSecretConfig           LDAPSecretConfig
	LDAPStaticRoleConfig       LDAPStaticRoleConfig
	LDAPDynamicRoleConfig      LDAPDynamicRoleConfig
	PctPostgreSQLRead          int
	PostgreSQLDBConfig         PostgreSQLDBConfig
	PostgreSQLRoleConfig       PostgreSQLRoleConfig
	PctCouchbaseRead           int
	CouchbaseConfig            CouchbaseConfig
	CouchbaseRoleConfig        CouchbaseRoleConfig
	PctKubernetesLogin         int
	KubernetesAuthConfig       KubernetesAuthConfig
	KubernetesTestRoleConfig   KubernetesTestRoleConfig
	PctSSHSign                 int
	SSHSignerCAConfig          SSHSignerCAConfig
	SSHSignerRoleConfig        SSHSignerRoleConfig
	PctPkiSign                 int
	PkiSignConfig              PkiSignTestConfig
	PctRedisDynamicRead        int
	PctRedisStaticRead         int
	RedisConfig                RedisConfig
	RedisDynamicRoleConfigJSON RedisDynamicRoleConfig
	RedisStaticRoleConfigJSON  RedisStaticRoleConfig
	Timeout                    time.Duration
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
			cleanup:    kvv1.cleanup,
		})
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "kvv1 write",
			method:     "POST",
			pathPrefix: kvv1.pathPrefix,
			percent:    spec.PctKvv1Write,
			target:     kvv1.write,
			cleanup:    kvv1.cleanup,
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
			cleanup:    kvv2.cleanup,
		})
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "kvv2 write",
			method:     "POST",
			pathPrefix: kvv2.pathPrefix,
			percent:    spec.PctKvv2Write,
			target:     kvv2.write,
			cleanup:    kvv2.cleanup,
		})
	}
	if spec.PctServiceTokenCreate > 0 || spec.PctBatchTokenCreate > 0 {
		tokenCreate := setupToken(client)
		tm.fractions = append(tm.fractions, targetFraction{
			name:    "service token",
			method:  "POST",
			percent: spec.PctServiceTokenCreate,
			target:  tokenCreate.createService,
			cleanup: tokenCreate.cleanup,
		})
		tm.fractions = append(tm.fractions, targetFraction{
			name:    "batch token",
			method:  "POST",
			percent: spec.PctBatchTokenCreate,
			target:  tokenCreate.createBatch,
			cleanup: tokenCreate.cleanup,
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
			cleanup:    approle.cleanup,
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
			cleanup:    cert.cleanup,
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
			cleanup:    ldap.cleanup,
		})
	}
	if spec.PctLDAPStaticRead > 0 {
		ldapsecret, err := setupLDAPStaticSecret(client, spec.RandomMounts, &spec.LDAPSecretConfig, &spec.LDAPStaticRoleConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "LDAP static read",
			method:     "GET",
			pathPrefix: ldapsecret.pathPrefix,
			percent:    spec.PctLDAPStaticRead,
			target:     ldapsecret.readStatic,
			cleanup:    ldapsecret.cleanup,
		})
	}
	if spec.PctLDAPStaticRotate > 0 {
		ldapsecret, err := setupLDAPStaticSecret(client, spec.RandomMounts, &spec.LDAPSecretConfig, &spec.LDAPStaticRoleConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "LDAP static rotate",
			method:     "POST",
			pathPrefix: ldapsecret.pathPrefix,
			percent:    spec.PctLDAPStaticRotate,
			target:     ldapsecret.rotateStatic,
			cleanup:    ldapsecret.cleanup,
		})
	}
	if spec.PctLDAPDynamicRead > 0 {
		ldapsecret, err := setupLDAPDynamicSecret(client, spec.RandomMounts, &spec.LDAPSecretConfig, &spec.LDAPDynamicRoleConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "LDAP dynamic read",
			method:     "GET",
			pathPrefix: ldapsecret.pathPrefix,
			percent:    spec.PctLDAPDynamicRead,
			target:     ldapsecret.readDynamic,
			cleanup:    ldapsecret.cleanup,
		})
	}
	if spec.PctKubernetesLogin > 0 {
		kubernetes, err := setupKubernetesAuth(client, spec.RandomMounts, &spec.KubernetesAuthConfig, &spec.KubernetesTestRoleConfig, spec.Timeout)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "Kubernetes login",
			method:     "POST",
			pathPrefix: kubernetes.pathPrefix,
			percent:    spec.PctKubernetesLogin,
			target:     kubernetes.login,
			cleanup:    kubernetes.cleanup,
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
			cleanup:    pki.cleanup,
		})
	}
	if spec.PctPkiSign > 0 {
		pkiSign, err := setupPKISigning(client, spec.RandomMounts, spec.PkiSignConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "pki sign",
			method:     "POST",
			pathPrefix: pkiSign.pathPrefix,
			percent:    spec.PctPkiSign,
			target:     pkiSign.sign,
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
			cleanup:    ssh.cleanup,
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
			cleanup:    status.cleanup,
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
			cleanup:    status.cleanup,
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
			cleanup:    status.cleanup,
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
			cleanup:    transit.cleanup,
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
			cleanup:    transit.cleanup,
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
			cleanup:    transit.cleanup,
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
			cleanup:    transit.cleanup,
		})
	}
	if spec.PctCassandraRead > 0 {
		cassandra, err := setupCassandra(client, spec.RandomMounts, &spec.CassandraDBConfig, &spec.CassandraDBRoleConfig, spec.Timeout)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "cassandra cred retrieval",
			method:     "GET",
			pathPrefix: cassandra.pathPrefix,
			percent:    spec.PctCassandraRead,
			target:     cassandra.read,
			cleanup:    cassandra.cleanup,
		})
	}
	if spec.PctMongoRead > 0 {
		mongo, err := setupMongo(client, spec.RandomMounts, &spec.MongoDBConfig, &spec.MongoDBRoleConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "mongo cred retrieval",
			method:     "GET",
			pathPrefix: mongo.pathPrefix,
			percent:    spec.PctMongoRead,
			target:     mongo.read,
			cleanup:    mongo.cleanup,
		})
	}

	if spec.PctRedisDynamicRead > 0 {
		redis, err := setupDynamicRoleRedis(client, spec.RandomMounts, &spec.RedisConfig, &spec.RedisDynamicRoleConfigJSON)
		if err != nil {
			return nil, err
		}

		tm.fractions = append(tm.fractions, targetFraction{
			name:       "redis dynamic cred retrieval",
			method:     "GET",
			pathPrefix: redis.pathPrefix,
			percent:    spec.PctRedisDynamicRead,
			target:     redis.readDynamic,
			cleanup:    redis.cleanup,
		})
	}

	if spec.PctRedisStaticRead > 0 {
		redis, err := setupStaticRoleRedis(client, spec.RandomMounts, &spec.RedisConfig, &spec.RedisStaticRoleConfigJSON)
		if err != nil {
			return nil, err
		}

		tm.fractions = append(tm.fractions, targetFraction{
			name:       "redis static cred retrieval",
			method:     "GET",
			pathPrefix: redis.pathPrefix,
			percent:    spec.PctRedisStaticRead,
			target:     redis.readStatic,
			cleanup:    redis.cleanup,
		})
	}

	if spec.PctRabbitRead > 0 {
		rabbit, err := setupRabbit(client, spec.RandomMounts, &spec.RabbitMQConfig, &spec.RabbitMQRoleConfig, spec.Timeout)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "rabbit cred retrieval",
			method:     "GET",
			pathPrefix: rabbit.pathPrefix,
			percent:    spec.PctRabbitRead,
			target:     rabbit.read,
			cleanup:    rabbit.cleanup,
		})
	}
	if spec.PctPostgreSQLRead > 0 {
		postgresql, err := setupPostgreSQL(client, spec.RandomMounts, &spec.PostgreSQLDBConfig, &spec.PostgreSQLRoleConfig, spec.Timeout)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "postgresql cred retrieval",
			method:     "GET",
			pathPrefix: postgresql.pathPrefix,
			percent:    spec.PctPostgreSQLRead,
			target:     postgresql.read,
			cleanup:    postgresql.cleanup,
		})
	}
	if spec.PctCouchbaseRead > 0 {
		couchbase, err := setupCouchbase(client, spec.RandomMounts, &spec.CouchbaseConfig, &spec.CouchbaseRoleConfig, spec.Timeout)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "couchbase cred retrieval",
			method:     "GET",
			pathPrefix: couchbase.pathPrefix,
			percent:    spec.PctCouchbaseRead,
			target:     couchbase.read,
			cleanup:    couchbase.cleanup,
		})
	}
	if spec.PctSSHSign > 0 {
		sshSign, err := setupSSHSign(client, spec.RandomMounts, &spec.SSHSignerCAConfig, &spec.SSHSignerRoleConfig)
		if err != nil {
			return nil, err
		}
		tm.fractions = append(tm.fractions, targetFraction{
			name:       "ssh pub key sign",
			method:     "POST",
			pathPrefix: sshSign.pathPrefix,
			percent:    spec.PctSSHSign,
			target:     sshSign.sign,
			cleanup:    sshSign.cleanup,
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
