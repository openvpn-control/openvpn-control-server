package agent

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Node is an agent endpoint row.
type Node struct {
	ID        string
	Name      string
	Protocol  string
	Host      string
	Port      int
	AuthToken string
}

func LoadNode(ctx context.Context, pool *pgxpool.Pool, id string) (Node, error) {
	var n Node
	err := pool.QueryRow(ctx,
		`SELECT id, name, protocol, host, port, "authToken" FROM "AgentNode" WHERE id = $1`, id,
	).Scan(&n.ID, &n.Name, &n.Protocol, &n.Host, &n.Port, &n.AuthToken)
	return n, err
}

func DisconnectClient(ctx context.Context, pool *pgxpool.Pool, nodeID, clientID string) (map[string]any, error) {
	n, err := LoadNode(ctx, pool, nodeID)
	if err != nil {
		return nil, err
	}
	return RequestJSON(ctx, n, "/clients/disconnect", http.MethodPost, map[string]string{"id": clientID})
}
