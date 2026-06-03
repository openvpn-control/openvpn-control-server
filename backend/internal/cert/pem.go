package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"hash"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

func ParseCertificate(pemText string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func ParsePrivateKey(pemText string) (any, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func KeysMatch(certPEM, keyPEM string) error {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return err
	}
	key, err := ParsePrivateKey(keyPEM)
	if err != nil {
		return err
	}
	certPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	keyPub, err := x509.MarshalPKIXPublicKey(extractPublic(key))
	if err != nil {
		return err
	}
	if !bytesEqual(certPub, keyPub) {
		return fmt.Errorf("Закрытый ключ не соответствует сертификату")
	}
	return nil
}

func extractPublic(key any) any {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func PemExpiryISO(certPEM string) *time.Time {
	c, err := ParseCertificate(certPEM)
	if err != nil {
		return nil
	}
	t := c.NotAfter.UTC()
	return &t
}

func SubjectCN(certPEM string) (string, error) {
	c, err := ParseCertificate(certPEM)
	if err != nil {
		return "", err
	}
	return c.Subject.CommonName, nil
}

func IsCAOrSelfSigned(certPEM string) bool {
	c, err := ParseCertificate(certPEM)
	if err != nil {
		return false
	}
	if c.IsCA {
		return true
	}
	return c.Subject.String() == c.Issuer.String() && c.Subject.CommonName != ""
}

func IsClientLeaf(certPEM string) bool {
	c, err := ParseCertificate(certPEM)
	if err != nil {
		return false
	}
	if c.IsCA {
		return false
	}
	if c.Subject.String() == c.Issuer.String() {
		return false
	}
	return true
}

func HasNegativeSerial(certPEM string) bool {
	c, err := ParseCertificate(certPEM)
	if err != nil {
		return false
	}
	return c.SerialNumber != nil && c.SerialNumber.Sign() < 0
}

func NormalizeSerialHex(serial string) string {
	s := strings.TrimSpace(serial)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	var digits strings.Builder
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			digits.WriteRune(r)
		}
	}
	d := digits.String()
	if d == "" {
		return ""
	}
	if len(d)%2 == 1 {
		d = "0" + d
	}
	b, err := hex.DecodeString(d)
	if err != nil {
		return strings.ToUpper(d)
	}
	return strings.ToUpper(new(big.Int).SetBytes(b).Text(16))
}

func SerialHex(cert *x509.Certificate) string {
	if cert == nil || cert.SerialNumber == nil {
		return ""
	}
	return NormalizeSerialHex(cert.SerialNumber.Text(16))
}

func DetectEncryptedKey(pemText string) bool {
	return strings.Contains(pemText, "BEGIN ENCRYPTED PRIVATE KEY") ||
		strings.Contains(strings.ToUpper(pemText), "ENCRYPTED")
}

type MaterialSummary struct {
	PairMatches              *bool    `json:"pairMatches"`
	FingerprintSha1          string   `json:"fingerprintSha1"`
	FingerprintSha256        string   `json:"fingerprintSha256"`
	FingerprintSha384        string   `json:"fingerprintSha384"`
	FingerprintSha512        string   `json:"fingerprintSha512"`
	CertificateSignatureHash string   `json:"certificateSignatureHash"`
	SerialNumber             string   `json:"serialNumber"`
	Algorithm                string   `json:"algorithm"`
	KeySize                  *int     `json:"keySize"`
	ValidTo                  *string  `json:"validTo"`
	Eku                      []string `json:"eku"`
	EncryptedPrivateKey      *bool    `json:"encryptedPrivateKey"`
}

func BuildMaterialSummary(certPEM, keyPEM string) MaterialSummary {
	out := MaterialSummary{
		CertificateSignatureHash: "sha256",
		Eku:                      []string{},
	}
	if certPEM == "" {
		if keyPEM != "" {
			v := DetectEncryptedKey(keyPEM)
			out.EncryptedPrivateKey = &v
		}
		return out
	}
	c, err := ParseCertificate(certPEM)
	if err != nil {
		return out
	}
	der := c.Raw
	out.FingerprintSha1 = fingerprint(der, sha1.New)
	out.FingerprintSha256 = fingerprint(der, sha256.New)
	out.FingerprintSha384 = fingerprint(der, sha512.New384)
	out.FingerprintSha512 = fingerprint(der, sha512.New)
	out.SerialNumber = c.SerialNumber.String()
	switch c.PublicKey.(type) {
	case *rsa.PublicKey:
		out.Algorithm = "rsa"
		if pk, ok := c.PublicKey.(*rsa.PublicKey); ok {
			n := pk.N.BitLen()
			out.KeySize = &n
		}
	case *ecdsa.PublicKey:
		out.Algorithm = "ec"
	}
	valid := c.NotAfter.UTC().Format(time.RFC3339)
	out.ValidTo = &valid
	if keyPEM == "" {
		return out
	}
	enc := DetectEncryptedKey(keyPEM)
	out.EncryptedPrivateKey = &enc
	if enc {
		return out
	}
	if err := KeysMatch(certPEM, keyPEM); err == nil {
		v := true
		out.PairMatches = &v
	} else {
		v := false
		out.PairMatches = &v
	}
	return out
}

func fingerprint(der []byte, newHash func() hash.Hash) string {
	h := newHash()
	_, _ = h.Write(der)
	hexStr := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	var parts []string
	for i := 0; i < len(hexStr); i += 2 {
		if i+2 <= len(hexStr) {
			parts = append(parts, hexStr[i:i+2])
		}
	}
	return strings.Join(parts, ":")
}

func EnsurePEMNewline(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
