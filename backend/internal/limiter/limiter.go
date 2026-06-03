package limiter

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

type loginState struct {
	failures    int
	lockedUntil int64
}

type Login struct {
	mu   sync.Mutex
	max  int
	lock time.Duration
	m    map[string]*loginState
}

func NewLogin(max int, lock time.Duration) *Login {
	return &Login{max: max, lock: lock, m: map[string]*loginState{}}
}

func (l *Login) Check(ip, username string) (ok bool, retryAfter int) {
	key := strings.ToLower(ip) + ":" + strings.ToLower(strings.TrimSpace(username))
	now := time.Now().UnixMilli()
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.m[key]
	if s != nil && s.lockedUntil > now {
		return false, int((s.lockedUntil-now)/1000) + 1
	}
	return true, 0
}

func (l *Login) Fail(ip, username string) {
	key := strings.ToLower(ip) + ":" + strings.ToLower(strings.TrimSpace(username))
	now := time.Now().UnixMilli()
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.m[key]
	if s == nil {
		s = &loginState{}
		l.m[key] = s
	}
	s.failures++
	if s.failures >= l.max {
		s.lockedUntil = now + l.lock.Milliseconds()
	}
}

func (l *Login) Success(ip, username string) {
	key := strings.ToLower(ip) + ":" + strings.ToLower(strings.TrimSpace(username))
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}

func ClientIP(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		return strings.TrimSpace(strings.Split(x, ",")[0])
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	if host != "" {
		return host
	}
	return r.RemoteAddr
}
