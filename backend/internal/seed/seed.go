package seed

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
)

func Run(ctx context.Context, pool *pgxpool.Pool, cfg config.Config) error {
	username := cfg.InitAdminUsername
	if username == "" {
		return fmt.Errorf("INIT_ADMIN_USERNAME is required")
	}
	var exists bool
	err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM "Admin" WHERE username = $1)`, username).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	password := cfg.InitAdminPassword
	if password == "" {
		return fmt.Errorf("INIT_ADMIN_PASSWORD is required for initial bootstrap")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	email := cfg.InitAdminEmail
	var emailVal any
	if email != "" {
		emailVal = email
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO "Admin" (id, "fullName", username, email, "passwordHash", "isActive", "createdAt", "updatedAt")
		VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())
	`, ksuid.New().String(), "Администратор", username, emailVal, string(hash))
	return err
}
