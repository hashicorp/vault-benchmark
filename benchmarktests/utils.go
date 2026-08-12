// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/mitchellh/mapstructure"
)

var (
	ErrIsDirectory = errors.New("location is a directory, not a file")
)

// resolveMountPath returns base unchanged, or a fresh UUID when random is true.
func resolveMountPath(base string, random bool) (string, error) {
	if !random {
		return base, nil
	}
	id, err := uuid.GenerateUUID()
	if err != nil {
		return "", fmt.Errorf("error generating random mount name: %w", err)
	}
	return id, nil
}

// writeStruct converts in to a map via structToMap and writes it to path.
func writeStruct(client *api.Client, path string, in any) error {
	data, err := structToMap(in)
	if err != nil {
		return fmt.Errorf("error serializing config for %q: %w", path, err)
	}
	if _, err := client.Logical().Write(path, data); err != nil {
		return fmt.Errorf("error writing %q: %w", path, err)
	}
	return nil
}

// Must not be copied after first use — embed by value only in structs accessed exclusively via pointer.
type cachedBody struct {
	mu     sync.Mutex
	body   []byte
	expiry time.Time
}

func omitEmpty(in any) {
	r := reflect.ValueOf(in)
	for _, e := range r.MapKeys() {
		v := r.MapIndex(e)
		if v.Elem().IsZero() {
			r.SetMapIndex(e, reflect.Value{})
		}
	}
}

func structToMap(in any) (map[string]any, error) {
	tMap := make(map[string]any)
	tDecoderConfig := mapstructure.DecoderConfig{
		Result:  &tMap,
		TagName: "hcl",
	}
	tDecoder, err := mapstructure.NewDecoder(&tDecoderConfig)
	if err != nil {
		return nil, fmt.Errorf("error configuring decoder: %v", err)
	}

	err = tDecoder.Decode(in)
	if err != nil {
		return nil, fmt.Errorf("error decoding role config from struct: %v", err)
	}
	omitEmpty(tMap)

	return tMap, nil
}

func GenerateCert(caCertTemplate *x509.Certificate, caSigner crypto.Signer) (string, string, error) {
	signer, keyPEM, err := privateKey()
	if err != nil {
		return "", "", fmt.Errorf("error generating private key for server certificate: %v", err)
	}

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

func GenerateCA() (*CaCert, error) {
	signer, _, err := privateKey()
	if err != nil {
		return nil, fmt.Errorf("error generating private key for CA: %v", err)
	}

	sn, err := serialNumber()
	if err != nil {
		return nil, fmt.Errorf("error generating serial number: %v", err)
	}

	signerKeyId, err := certutil.GetSubjKeyID(signer)
	if err != nil {
		return nil, fmt.Errorf("error getting subject key id from key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "Vault Benchmark CA"},
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

func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
}

func generateHeader(client *api.Client) http.Header {
	return http.Header{
		"X-Vault-Token":     []string{client.Token()},
		"X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")},
	}
}

func IsFile(path string) (bool, error) {
	f, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	if f.IsDir() {
		return false, ErrIsDirectory
	}

	return true, nil
}

// natLess reports whether a should sort before b using natural ordering
// rather than lexicographically, resulting in "test2" before "test11".
func natLess(a, b string) bool {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		aDigit := a[i] >= '0' && a[i] <= '9'
		bDigit := b[j] >= '0' && b[j] <= '9'

		switch {
		case aDigit && bDigit:
			startA, startB := i, j
			for i < len(a) && a[i] >= '0' && a[i] <= '9' {
				i++
			}
			for j < len(b) && b[j] >= '0' && b[j] <= '9' {
				j++
			}

			numA := strings.TrimLeft(a[startA:i], "0")
			numB := strings.TrimLeft(b[startB:j], "0")
			if len(numA) != len(numB) {
				return len(numA) < len(numB)
			}
			if numA != numB {
				return numA < numB
			}
			// Equal value: fewer leading zeros sorts first for stability.
			if (i - startA) != (j - startB) {
				return (i - startA) < (j - startB)
			}
		case aDigit != bDigit:
			return aDigit
		default:
			if a[i] != b[j] {
				return a[i] < b[j]
			}
			i++
			j++
		}
	}

	return len(a)-i < len(b)-j
}

func natSort(s []string) {
	sort.Slice(s, func(i, j int) bool {
		return natLess(s[i], s[j])
	})
}

// ceilDiv returns ceil(a/b) for b > 0.
func ceilDiv(a, b int) int {
	return (a + b - 1) / b
}
