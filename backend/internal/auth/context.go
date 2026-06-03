package auth

import (
	"context"
	"net/http"
)

type ctxKey int

const userCtxKey ctxKey = 1

func WithUser(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, userCtxKey, claims)
}

func UserFromRequest(r *http.Request) *Claims {
	c, _ := r.Context().Value(userCtxKey).(*Claims)
	return c
}
