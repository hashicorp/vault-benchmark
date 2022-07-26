package vegeta

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type certTest struct {
	pathPrefix string
	header     http.Header
}

type CaCert struct {
	PEM      string
	Template *x509.Certificate
	Signer   crypto.Signer
}

// GenerateCert creates a new leaf cert from provided CA template and signer
func GenerateCert(caCertTemplate *x509.Certificate, caSigner crypto.Signer) (string, string, error) {
	// Create the private key
	signer, keyPEM, err := privateKey()
	if err != nil {
		return "", "", fmt.Errorf("error generating private key for server certificate: %v", err)
	}

	// The serial number for the cert
	sn, err := serialNumber()
	if err != nil {
		return "", "", fmt.Errorf("error generating serial number: %v", err)
	}

	signerKeyId, err := certutil.GetSubjKeyID(signer)
	if err != nil {
		return "", "", fmt.Errorf("error getting subject key id from key: %v", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		return "", "", fmt.Errorf("error getting hostname: %v", err)
	}

	if hostname == "" {
		hostname = "localhost"
	}

	// Create the leaf cert
	template := x509.Certificate{
		SerialNumber:   sn,
		Subject:        pkix.Name{CommonName: hostname},
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		NotBefore:      time.Now().Add(-1 * time.Minute),
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:       []string{"localhost", "localhost4", "localhost6", "localhost.localdomain"},
		AuthorityKeyId: caCertTemplate.AuthorityKeyId,
		SubjectKeyId:   signerKeyId,
	}

	bs, err := x509.CreateCertificate(
		rand.Reader, &template, caCertTemplate, signer.Public(), caSigner)
	if err != nil {
		return "", "", fmt.Errorf("error creating server certificate: %v", err)
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: bs})
	if err != nil {
		return "", "", fmt.Errorf("error encoding server certificate: %v", err)
	}

	return buf.String(), keyPEM, nil
}

// GenerateCA generates a new self-signed CA cert and returns a
// CaCert struct containing the PEM encoded cert,
// X509 Certificate Template, and crypto.Signer
func GenerateCA() (*CaCert, error) {
	// Create the private key we'll use for this CA cert.
	signer, _, err := privateKey()
	if err != nil {
		return nil, fmt.Errorf("error generating private key for CA: %v", err)
	}

	// The serial number for the cert
	sn, err := serialNumber()
	if err != nil {
		return nil, fmt.Errorf("error generating serial number: %v", err)
	}

	signerKeyId, err := certutil.GetSubjKeyID(signer)
	if err != nil {
		return nil, fmt.Errorf("error getting subject key id from key: %v", err)
	}

	// Create the CA cert
	template := x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "Benchmark Vault CA"},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		NotBefore:             time.Now().Add(-1 * time.Minute),
		AuthorityKeyId:        signerKeyId,
		SubjectKeyId:          signerKeyId,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	bs, err := x509.CreateCertificate(
		rand.Reader, &template, &template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("error creating CA certificate: %v", err)
	}

	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: bs})
	if err != nil {
		return nil, fmt.Errorf("error encoding CA certificate: %v", err)
	}
	return &CaCert{
		PEM:      buf.String(),
		Template: &template,
		Signer:   signer,
	}, nil
}

// privateKey returns a new ECDSA-based private key. Both a crypto.Signer
// and the key in PEM format are returned.
func privateKey() (crypto.Signer, string, error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	bs, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		return nil, "", err
	}

	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: bs})
	if err != nil {
		return nil, "", err
	}

	return pk, buf.String(), nil
}

// serialNumber generates a new random serial number.
func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
}

func setupCert(client *api.Client, randomMounts bool, ttl time.Duration, clientCAPem string) (*certTest, error) {
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
		"certificate":   clientCAPem,
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
