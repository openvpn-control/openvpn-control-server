package agent

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ProcessPanelTasks runs queued panel tasks for an online node (set from worker to avoid import cycles).
var ProcessPanelTasks func(ctx context.Context, pool *pgxpool.Pool, n Node, maxTasks int)
