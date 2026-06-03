package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/ksuid"
)

// Run applies pending Prisma SQL migrations from dir (…/prisma/migrations).
func Run(ctx context.Context, pool *pgxpool.Pool, dir string) error {
	if dir == "" {
		dir = "prisma/migrations"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	if err := ensureTable(ctx, pool); err != nil {
		return err
	}

	for _, name := range names {
		sqlPath := filepath.Join(dir, name, "migration.sql")
		if _, err := os.Stat(sqlPath); err != nil {
			continue
		}
		applied, err := isApplied(ctx, pool, name)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := os.ReadFile(sqlPath)
		if err != nil {
			return err
		}
		if err := applyOne(ctx, pool, name, sha256Hex(body), string(body)); err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
	}
	return nil
}

func ensureTable(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS "_prisma_migrations" (
			"id" VARCHAR(36) NOT NULL PRIMARY KEY,
			"checksum" VARCHAR(64) NOT NULL,
			"finished_at" TIMESTAMPTZ,
			"migration_name" VARCHAR(255) NOT NULL,
			"logs" TEXT,
			"rolled_back_at" TIMESTAMPTZ,
			"started_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
			"applied_steps_count" INTEGER NOT NULL DEFAULT 0
		)`)
	return err
}

func isApplied(ctx context.Context, pool *pgxpool.Pool, name string) (bool, error) {
	var n int
	err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM "_prisma_migrations" WHERE "migration_name" = $1 AND "finished_at" IS NOT NULL`,
		name,
	).Scan(&n)
	return n > 0, err
}

func applyOne(ctx context.Context, pool *pgxpool.Pool, name, checksum, sql string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	id := ksuid.New().String()
	_, err = tx.Exec(ctx, `
		INSERT INTO "_prisma_migrations" ("id", "checksum", "migration_name", "started_at", "applied_steps_count")
		VALUES ($1, $2, $3, now(), 1)`,
		id, checksum, name,
	)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sql); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE "_prisma_migrations" SET "finished_at" = now() WHERE "id" = $1`, id)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
