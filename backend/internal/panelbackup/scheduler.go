package panelbackup

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
)

var (
	schedulerMu sync.Mutex
	running     bool
)

func Start(ctx context.Context, pool *pgxpool.Pool, cfg config.Config) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tick(ctx, pool, cfg)
			}
		}
	}()
}

func tick(ctx context.Context, pool *pgxpool.Pool, cfg config.Config) {
	schedulerMu.Lock()
	if running {
		schedulerMu.Unlock()
		return
	}
	running = true
	schedulerMu.Unlock()
	defer func() {
		schedulerMu.Lock()
		running = false
		schedulerMu.Unlock()
	}()

	s, err := EnsureBackupSettingsRow(ctx, pool)
	if err != nil {
		log.Printf("[panel-backup-scheduler] %v", err)
		return
	}
	if s.IntervalMinutes <= 0 {
		return
	}
	if s.LastScheduledAt == nil {
		return
	}
	due := s.LastScheduledAt.Add(time.Duration(s.IntervalMinutes) * time.Minute)
	if time.Now().Before(due) {
		return
	}
	if _, err := CreatePanelBackupZip(ctx, pool, cfg.PanelBackupDir, "scheduled"); err != nil {
		log.Printf("[panel-backup-scheduler] %v", err)
		return
	}
	now := time.Now()
	_, _ = pool.Exec(ctx, `UPDATE "PanelAppBackupSettings" SET "lastScheduledAt" = $1, "updatedAt" = NOW() WHERE id = 1`, now)
}
