package benchmark_tests

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/mitchellh/mapstructure"
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

// ConfigOverrides accepts a config interface and will walk through all passed in flags
// and set the relevant config parameters that match based on hcl tag. This expects the
// tag name and the flag name to match. By this point everything should have gone through
// HCL parsing and flag parsing.
func ConfigOverrides(conf interface{}) error {
	var err error
	flag.Visit(func(f *flag.Flag) {
		// Walk all the keys of the config struct
		r := reflect.ValueOf(conf).Elem()

		for i := 0; i < r.NumField(); i++ {
			// We expect the config flag so skip this one
			if f.Name == "config" {
				continue
			}
			// Get Field name match by tag
			tag := r.Type().Field(i).Tag.Get("hcl")
			if tag == "" || tag == "-" {
				continue
			}
			args := strings.Split(tag, ",")

			// Match the flag against the tag
			if args[0] == f.Name {
				if r.Field(i).CanSet() {
					switch r.Field(i).Kind() {
					case reflect.Bool:
						r.Field(i).SetBool(f.Value.(flag.Getter).Get().(bool))
					case reflect.String:
						// Check if we need to grab the string value of a time.Duration flag
						if t, ok := f.Value.(flag.Getter).Get().(time.Duration); ok {
							r.Field(i).SetString(t.String())
							continue
						}
						r.Field(i).SetString(f.Value.(flag.Getter).Get().(string))
					case reflect.Int:
						r.Field(i).SetInt(f.Value.(flag.Getter).Get().(int64))
					}
				} else {
					// Unable to set
					err = fmt.Errorf("unable to set field: %v", f.Name)
				}
			}
			fmt.Printf("unable to find match for flag %v\n", f.Name)
		}
	})
	return err
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
