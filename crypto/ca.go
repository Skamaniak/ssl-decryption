package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

func readPrivateKey(rsaPrivateKeyLocation, rsaPrivateKeyPassword string) (*rsa.PrivateKey, error) {
	if rsaPrivateKeyLocation == "" {
		return nil, errors.New("location of the key was not specified")
	}

	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		return nil, err
	}

	privPem, _ := pem.Decode(priv)
	if privPem.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("unexpected private key type: " + privPem.Type)
	}

	var privPemBytes []byte
	if rsaPrivateKeyPassword != "" {
		privPemBytes, err = x509.DecryptPEMBlock(privPem, []byte(rsaPrivateKeyPassword))
	} else {
		privPemBytes = privPem.Bytes
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil {
			return nil, err
		}
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("unable to parse RSA private key")
	}

	return privateKey, nil
}

func readCertificate(rsaCertificateLocation string) (*x509.Certificate, error) {
	r, err := ioutil.ReadFile(rsaCertificateLocation)
	if err != nil {
		return nil, err
	}
	var block *pem.Block
	block, _ = pem.Decode(r)
	return x509.ParseCertificate(block.Bytes)
}

type CertificationAuthority struct {
	Cert       *x509.Certificate
	PrivateKey *rsa.PrivateKey
}

func ReadCertificationAuthority(certLocation, privateKeyLocation, privateKeyPwd string) (CertificationAuthority, error) {
	cert, err := readCertificate(certLocation)
	if err != nil {
		return CertificationAuthority{}, err
	}

	privateKey, err := readPrivateKey(privateKeyLocation, privateKeyPwd)
	if err != nil {
		return CertificationAuthority{}, err
	}
	return CertificationAuthority{
		Cert:       cert,
		PrivateKey: privateKey,
	}, nil
}
