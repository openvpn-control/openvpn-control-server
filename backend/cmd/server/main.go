package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/openvpn-control/openvpn-control-server/backend/internal/config"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/db"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/migrate"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/panelbackup"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/seed"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/server"
	"github.com/openvpn-control/openvpn-control-server/backend/internal/worker"
)

func main() {
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	migrationsDir := os.Getenv("PRISMA_MIGRATIONS_DIR")
	if migrationsDir == "" {
		migrationsDir = "prisma/migrations"
	}
	if err := migrate.Run(ctx, pool, migrationsDir); err != nil {
		log.Fatal("migrate: ", err)
	}

	if err := seed.Run(ctx, pool, cfg); err != nil {
		log.Fatal("seed: ", err)
	}

	worker.Start(ctx, pool, cfg)
	panelbackup.Start(ctx, pool, cfg)

	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.Port),
		Handler:           server.NewRouter(cfg, pool),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("Backend (Go) listening on port %d", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}
