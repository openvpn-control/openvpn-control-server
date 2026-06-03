package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

func IssueLeaf(caCertPEM, caKeyPEM, commonName string, validityDays int) (certPEM, keyPEM string, expiresAt time.Time, serial string, err error) {
	caCert, err := ParseCertificate(caCertPEM)
	if err != nil {
		return "", "", time.Time{}, "", err
	}
	caKey, err := ParsePrivateKey(caKeyPEM)
	if err != nil {
		return "", "", time.Time{}, "", err
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", time.Time{}, "", err
	}
	days := validityDays
	if days < 1 {
		days = 365
	}
	if days > 3650 {
		days = 3650
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)
	serialNum, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", time.Time{}, "", err
	}
	template := x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKeyAny(caKey))
	if err != nil {
		return "", "", time.Time{}, "", err
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", time.Time{}, "", err
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	leaf, _ := x509.ParseCertificate(der)
	if leaf != nil {
		serial = SerialHex(leaf)
		expiresAt = leaf.NotAfter
	}
	return certPEM, keyPEM, expiresAt, serial, nil
}

func GenerateRootCA(commonName string, days, keyBits int) (certPEM, keyPEM string, err error) {
	if keyBits < 2048 {
		keyBits = 2048
	}
	if keyBits > 8192 {
		keyBits = 8192
	}
	if days < 1 {
		days = 3650
	}
	if days > 3650 {
		days = 3650
	}
	priv, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return "", "", err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, nil
}

func caKeyAny(key any) any {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k
	default:
		return key
	}
}

func VerifyIssuedByRoot(leafPEM, rootPEM string) error {
	leaf, err := ParseCertificate(leafPEM)
	if err != nil {
		return err
	}
	root, err := ParseCertificate(rootPEM)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots})
	if err != nil {
		return fmt.Errorf("Импорт невозможен: сертификат подписан не корневым сертификатом этого сервера.")
	}
	return nil
}
