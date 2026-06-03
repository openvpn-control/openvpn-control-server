package crl

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type RevokedRow struct {
	SerialNumber string
	CommonName   string
	ExpiresAt    time.Time
	RevokedAt    time.Time
}

func GeneratePEM(caCertPEM, caKeyPEM string, revoked []RevokedRow) (string, error) {
	tmp, err := os.MkdirTemp("", "ovpn-crl-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	if err := os.WriteFile(filepath.Join(tmp, "ca.crt"), []byte(caCertPEM), 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(tmp, "ca.key"), []byte(caKeyPEM), 0o600); err != nil {
		return "", err
	}

	var indexLines []string
	for _, c := range revoked {
		serialHex := serialToOpenSSLHex(c.SerialNumber)
		exp := toOpenSSLUTC(c.ExpiresAt)
		rev := toOpenSSLUTC(c.RevokedAt)
		cn := strings.ReplaceAll(c.CommonName, "\t", " ")
		cn = strings.ReplaceAll(cn, "\n", " ")
		cn = strings.ReplaceAll(cn, "\r", " ")
		if cn == "" {
			cn = "unknown"
		}
		indexLines = append(indexLines, fmt.Sprintf("R\t%s\t%s\t%s\tunknown\t/CN=%s", exp, rev, serialHex, cn))
	}
	indexContent := strings.Join(indexLines, "\n")
	if indexContent != "" {
		indexContent += "\n"
	}
	_ = os.WriteFile(filepath.Join(tmp, "index.txt"), []byte(indexContent), 0o600)
	_ = os.WriteFile(filepath.Join(tmp, "index.txt.attr"), []byte("unique_subject = no\n"), 0o600)
	_ = os.WriteFile(filepath.Join(tmp, "serial"), []byte("01\n"), 0o600)
	_ = os.WriteFile(filepath.Join(tmp, "crlnumber"), []byte("01\n"), 0o600)

	dirUnix := filepath.ToSlash(tmp)
	cnf := fmt.Sprintf(`[ ca ]
default_ca = CA_default

[ CA_default ]
database = %s/index.txt
certificate = %s/ca.crt
serial = %s/serial
crlnumber = %s/crlnumber
private_key = %s/ca.key
default_md = sha256
default_crl_days = 30
unique_subject = no
`, dirUnix, dirUnix, dirUnix, dirUnix, dirUnix)
	if err := os.WriteFile(filepath.Join(tmp, "openssl.cnf"), []byte(cnf), 0o600); err != nil {
		return "", err
	}

	cmd := exec.Command("openssl", "ca", "-config", "openssl.cnf", "-gencrl", "-out", "crl.pem")
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	data, err := os.ReadFile(filepath.Join(tmp, "crl.pem"))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func serialToOpenSSLHex(serial string) string {
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(serial, "0x"), "0X"))
	if s == "" {
		return "01"
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return strings.ToUpper(s)
		}
	}
	return strings.ToUpper(s)
}

func toOpenSSLUTC(d time.Time) string {
	if d.IsZero() {
		return "00000000000000Z"
	}
	y := d.UTC().Year() % 100
	return fmt.Sprintf("%02d%02d%02d%02d%02d%02dZ",
		y, int(d.UTC().Month()), d.UTC().Day(),
		d.UTC().Hour(), d.UTC().Minute(), d.UTC().Second())
}
