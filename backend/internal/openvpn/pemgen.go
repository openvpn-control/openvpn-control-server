package openvpn

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// FirstTlsAuthPath returns the file path from a tls-auth directive line.
func FirstTlsAuthPath(tlsAuthLine string) string {
	s := strings.TrimSpace(tlsAuthLine)
	if s == "" {
		return ""
	}
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// GenerateDhPem2048 runs openssl dhparam.
func GenerateDhPem2048() (string, error) {
	cmd := exec.Command("openssl", "dhparam", "-outform", "PEM", "2048")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// GenerateTlsAuthKeyPem generates an OpenVPN static key via openvpn --genkey or fallback.
func GenerateTlsAuthKeyPem() (string, error) {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("ov-ta-%d.key", os.Getpid()))
	defer os.Remove(tmp)
	cmd := exec.Command("openvpn", "--genkey", "secret", tmp)
	if err := cmd.Run(); err == nil {
		data, readErr := os.ReadFile(tmp)
		if readErr == nil {
			return string(data), nil
		}
	}
	return generateTlsAuthStaticKeyFallback(), nil
}

func generateTlsAuthStaticKeyFallback() string {
	buf := make([]byte, 256)
	_, _ = rand.Read(buf)
	var lines []string
	for i := 0; i < 16; i++ {
		lines = append(lines, fmt.Sprintf("%x", buf[i*16:(i+1)*16]))
	}
	return "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n" +
		strings.Join(lines, "\n") + "\n-----END OpenVPN Static key V1-----\n"
}
