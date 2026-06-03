package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"
)

const recoveryCodeCount = 10

func NormalizeRecoveryCodeInput(raw string) string {
	s := strings.ReplaceAll(raw, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	return strings.ToLower(s)
}

func formatRecoveryCode(bytes []byte) string {
	h := hex.EncodeToString(bytes)
	return fmt.Sprintf("%s-%s-%s-%s", h[0:4], h[4:8], h[8:12], h[12:16])
}

// ReplaceRecoveryCodesForAdmin deletes existing codes and inserts fresh ones inside tx.
func ReplaceRecoveryCodesForAdmin(ctx context.Context, tx pgx.Tx, adminID string) ([]string, error) {
	if _, err := tx.Exec(ctx, `DELETE FROM "AdminTotpRecoveryCode" WHERE "adminId" = $1`, adminID); err != nil {
		return nil, err
	}
	plainCodes := make([]string, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		plain := formatRecoveryCode(b)
		plainCodes = append(plainCodes, plain)
		normalized := NormalizeRecoveryCodeInput(plain)
		hash, err := bcrypt.GenerateFromPassword([]byte(normalized), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO "AdminTotpRecoveryCode" (id, "adminId", "codeHash", "createdAt")
			VALUES ($1, $2, $3, NOW())`, newRecoveryCodeID(), adminID, string(hash)); err != nil {
			return nil, err
		}
	}
	return plainCodes, nil
}

func newRecoveryCodeID() string {
	return ksuid.New().String()
}

// VerifyAndConsumeRecoveryCode checks a recovery code and marks it used on success.
func VerifyAndConsumeRecoveryCode(ctx context.Context, pool *pgxpool.Pool, adminID, rawCode string) bool {
	normalized := NormalizeRecoveryCodeInput(rawCode)
	if len(normalized) < 16 {
		return false
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT id, "codeHash" FROM "AdminTotpRecoveryCode"
		WHERE "adminId" = $1 AND "usedAt" IS NULL`, adminID)
	if err != nil {
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var id, hash string
		if rows.Scan(&id, &hash) != nil {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(normalized)) != nil {
			continue
		}
		tag, err := tx.Exec(ctx, `
			UPDATE "AdminTotpRecoveryCode" SET "usedAt" = NOW()
			WHERE id = $1 AND "usedAt" IS NULL`, id)
		if err != nil || tag.RowsAffected() != 1 {
			return false
		}
		return tx.Commit(ctx) == nil
	}
	return false
}
