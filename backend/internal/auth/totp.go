package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

func encryptionKey(jwtSecret string) []byte {
	sum := sha256.Sum256([]byte(jwtSecret))
	return sum[:]
}

func EncryptSecret(jwtSecret, secret string) (string, error) {
	key := encryptionKey(jwtSecret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), nil)
	tag := ciphertext[len(ciphertext)-gcm.Overhead():]
	data := ciphertext[:len(ciphertext)-gcm.Overhead()]
	return fmt.Sprintf("%s:%s:%s",
		base64.StdEncoding.EncodeToString(nonce),
		base64.StdEncoding.EncodeToString(tag),
		base64.StdEncoding.EncodeToString(data),
	), nil
}

func DecryptSecret(jwtSecret, payload string) (string, error) {
	parts := strings.Split(payload, ":")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid payload")
	}
	iv, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	tag, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", err
	}
	key := encryptionKey(jwtSecret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	combined := append(data, tag...)
	plain, err := gcm.Open(nil, iv, combined, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func VerifyTotp(secret, code string) bool {
	code = strings.ReplaceAll(code, " ", "")
	if code == "" {
		return false
	}
	return totp.Validate(code, secret)
}

func GenerateTotpKey(issuer, account string) (secret string, otpauth string, err error) {
	k, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
	if err != nil {
		return "", "", err
	}
	return k.Secret(), k.URL(), nil
}

func GenerateTotpQRDataURL(otpauthURL string) (string, error) {
	if strings.TrimSpace(otpauthURL) == "" {
		return "", fmt.Errorf("empty otpauth url")
	}
	png, err := qrcode.Encode(otpauthURL, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
