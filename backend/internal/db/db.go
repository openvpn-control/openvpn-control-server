package db

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Prisma adds ?schema=public to DATABASE_URL; pgx/libpq does not accept that parameter.
var prismaQueryKeys = []string{
	"schema",
	"connection_limit",
	"pool_timeout",
	"connect_timeout",
	"socket_timeout",
	"pgbouncer",
}

func Connect(ctx context.Context) (*pgxpool.Pool, error) {
	raw := os.Getenv("DATABASE_URL")
	if raw == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	connURL, err := normalizeDatabaseURL(raw)
	if err != nil {
		return nil, fmt.Errorf("DATABASE_URL: %w", err)
	}
	return pgxpool.New(ctx, connURL)
}

func normalizeDatabaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for _, k := range prismaQueryKeys {
		q.Del(k)
	}
	if q.Get("sslmode") == "" {
		q.Set("sslmode", "disable")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
