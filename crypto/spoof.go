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

func spoofCertificate(domain string) *x509.Certificate {
	validityYears := viper.GetInt(conf.SpoofedCertValidityYears)

	return &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"You've been pwned my buddy!"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Secretvill"},
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

func readCertificationAuthority() (CertificationAuthority, error) {
	caCertLocation := viper.GetString(conf.CaCertLocation)
	caKeyLocation := viper.GetString(conf.CaKeyLocation)
	caKeyPassword := viper.GetString(conf.CaKeyPassword)
	return ReadCertificationAuthority(caCertLocation, caKeyLocation, caKeyPassword)
}

func GenerateSpoofedServerCertificate(domain string) (*tls.Certificate, error) {
	ca, err := readCertificationAuthority()
	if err != nil {
		return nil, err
	}

	cert := spoofCertificate(domain)

	var spoofedCertPrivKey *rsa.PrivateKey
	spoofedCertPrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	var spoofedCertBytes []byte
	spoofedCertBytes, err = x509.CreateCertificate(rand.Reader, cert, ca.Cert, &spoofedCertPrivKey.PublicKey, ca.PrivateKey)
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
		Bytes: x509.MarshalPKCS1PrivateKey(spoofedCertPrivKey),
	})
	if err != nil {
		return nil, err
	}

	serverCert, err := tls.X509KeyPair(spoofedCertPem.Bytes(), spoofedCertPrivKeyPem.Bytes())
	return &serverCert, nil

}
