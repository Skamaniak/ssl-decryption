package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/spf13/viper"
	"math/big"
	"ssl-decryption/conf"
	"time"
)

func readCertificationAuthority() (CertificationAuthority, error) {
	caCertLocation := viper.GetString(conf.CaCertLocation)
	caKeyLocation := viper.GetString(conf.CaKeyLocation)
	caKeyPassword := viper.GetString(conf.CaKeyPassword)
	return ReadCertificationAuthority(caCertLocation, caKeyLocation, caKeyPassword)
}

func NewCertSpoofer() (*CertSpoofer, error) {
	ca, err := readCertificationAuthority()
	if err != nil {
		return nil, err
	}
	// Generate one and use it for signing all the generated certs #security :P
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	certSpoofer := CertSpoofer{certAuthority: ca, privateKey: privKey}
	return &certSpoofer, nil
}

type CertSpoofer struct {
	certAuthority CertificationAuthority
	privateKey    *rsa.PrivateKey
}

func (c *CertSpoofer) spoofCertificate(domain string) *x509.Certificate {
	validityYears := viper.GetInt(conf.SpoofedCertValidityYears)

	return &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"You've been pwned buddy!"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Secretville"},
			StreetAddress: []string{"Concealed"},
			PostalCode:    []string{"314159"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(validityYears, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{domain},
	}
}

func (c *CertSpoofer) GenerateSpoofedServerCertificate(domain string) (*tls.Certificate, error) {
	cert := c.spoofCertificate(domain)

	var spoofedCertBytes []byte
	ca := c.certAuthority
	spoofedCertBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.Cert, &c.privateKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	spoofedCertPem := new(bytes.Buffer)
	err = pem.Encode(spoofedCertPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: spoofedCertBytes,
	})
	if err != nil {
		return nil, err
	}

	spoofedCertPrivKeyPem := new(bytes.Buffer)
	err = pem.Encode(spoofedCertPrivKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(c.privateKey),
	})
	if err != nil {
		return nil, err
	}

	serverCert, err := tls.X509KeyPair(spoofedCertPem.Bytes(), spoofedCertPrivKeyPem.Bytes())
	return &serverCert, nil

}
