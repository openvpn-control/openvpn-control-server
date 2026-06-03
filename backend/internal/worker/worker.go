package worker

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/agent"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/paneltasks"
)

func Start(ctx context.Context, pool *pgxpool.Pool, cfg config.Config) {
	agent.ProcessPanelTasks = paneltasks.ProcessPendingForNode
	go loop(ctx, pool, cfg, cfg.AgentSyncInterval, "agent", func(ctx context.Context) error {
		_, err := agent.SyncAllNodes(ctx, pool, cfg)
		return err
	})
	go guardedLoop(ctx, pool, cfg, cfg.OpenvpnInfoSyncInterval, "openvpn-info", func(ctx context.Context) error {
		_, err := agent.SyncAllOpenVPNInfo(ctx, pool, cfg)
		return err
	})
	go guardedLoop(ctx, pool, cfg, cfg.ClientSyncInterval, "client", func(ctx context.Context) error {
		return agent.SyncClientsSnapshot(ctx, pool, cfg)
	})
}

func loop(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, interval time.Duration, name string, fn func(context.Context) error) {
	t := time.NewTicker(interval)
	defer t.Stop()
	run := func() {
		if err := fn(ctx); err != nil {
			log.Printf("%s sync: %v", name, err)
		}
	}
	run()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

func guardedLoop(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, interval time.Duration, name string, fn func(context.Context) error) {
	var inFlight atomic.Bool
	t := time.NewTicker(interval)
	defer t.Stop()
	run := func() {
		if !inFlight.CompareAndSwap(false, true) {
			return
		}
		defer inFlight.Store(false)
		if err := fn(ctx); err != nil {
			log.Printf("%s sync: %v", name, err)
		}
	}
	run()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
