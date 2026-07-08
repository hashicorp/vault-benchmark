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
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/mitchellh/mapstructure"
)

var (
	ErrIsDirectory = errors.New("location is a directory, not a file")
)

func omitEmpty(in interface{}) {
	r := reflect.ValueOf(in)
	for _, e := range r.MapKeys() {
		// If the value is its zero value, we don't want to add it to
		// the resulting map.
		v := r.MapIndex(e)
		if v.Elem().IsZero() {
			r.SetMapIndex(e, reflect.Value{})
		}
	}
}

// structToMap decodes the config structs defined in tests to maps so
// they can be passed in as part of the Vault API request
func structToMap(in interface{}) (map[string]interface{}, error) {
	tMap := make(map[string]interface{})
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

func generateHeader(client *api.Client) http.Header {
	return http.Header{
		"X-Vault-Token":     []string{client.Token()},
		"X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")},
	}
}

func IsFile(path string) (bool, error) {
	// File Validity checking
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
			// Consume the full digit run from each string.
			startA, startB := i, j
			for i < len(a) && a[i] >= '0' && a[i] <= '9' {
				i++
			}
			for j < len(b) && b[j] >= '0' && b[j] <= '9' {
				j++
			}

			// Compare by numeric value, ignoring leading zeros.
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
			// A numeric segment sorts before a non-numeric one.
			return aDigit
		default:
			if a[i] != b[j] {
				return a[i] < b[j]
			}
			i++
			j++
		}
	}

	// Whichever string has characters remaining is the longer one.
	return len(a)-i < len(b)-j
}

// natSort sorts a slice of strings in place using natural ordering
func natSort(s []string) {
	sort.Slice(s, func(i, j int) bool {
		return natLess(s[i], s[j])
	})
}
